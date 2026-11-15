
export type Finding = {
  id: string;
  ruleId: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  file: string;
  line: number;
  explanation: string;
  fix: string;
  evidence: string;
};

export type ScannedFile = {
  path: string;
  text: string;
};

const PLACEHOLDERS =
  /^(your[_ -].*|example.*|changeme|replace[_ -]?me|xxx+|<.*>|\*+|\*{3,})$/i;

function redact(value: string) {
  if (value.length <= 8) return "[REDACTED]";
  return value.slice(0, 4) + "…" + value.slice(-3);
}

function add(
  findings: Finding[],
  file: ScannedFile,
  ruleId: string,
  title: string,
  severity: Finding["severity"],
  line: number,
  explanation: string,
  fix: string,
  evidence: string
) {
  findings.push({
    id: `${ruleId}:${file.path}:${line}`,
    ruleId,
    title,
    severity,
    file: file.path,
    line,
    explanation,
    fix,
    evidence,
  });
}

function hasHighEntropy(value: string): boolean {
  if (value.length < 20) return false;

  const frequencies = new Map<string, number>();

  for (const char of value) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;

  for (const count of frequencies.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy >= 3.5;
}

export function scanFiles(files: ScannedFile[]) {
  const findings: Finding[] = [];

  const envNames = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
  ];

  for (const file of files) {
    const base = file.path.split("/").pop() || file.path;
    const lines = file.text.split(/\r?\n/);

    // Environment file detection
    if (envNames.includes(base)) {
      const meaningful = lines.filter(
        (l) =>
          /^[A-Za-z_][A-Za-z0-9_]*\s*=\s*.+/.test(l) &&
          !/=\s*(['"]?)(your_|example|changeme|xxx)/i.test(l),
      );

      add(
        findings,
        file,
        "ENV_FILE",
        "Environment file included in project archive",
        meaningful.length ? "high" : "low",
        1,
        "Environment files often contain credentials and private configuration. This archive includes an environment file.",
        "Remove real .env files from shared archives. Keep a sanitized .env.example and load secrets from environment variables.",
        meaningful.length
          ? `${meaningful.length} variable assignment(s); values hidden`
          : "Environment file detected; values not displayed",
      );
    }

    // .gitignore detection
    if (
      file.path.endsWith(".gitignore") &&
      !file.text
        .split(/\r?\n/)
        .some((l) => l.trim() === ".env" || l.trim() === ".env*")
    ) {
      add(
        findings,
        file,
        "GITIGNORE_ENV",
        ".gitignore may not exclude environment files",
        "low",
        1,
        "Without an ignore rule, local environment files can accidentally be committed.",
        "Add .env* to .gitignore, then explicitly allow a sanitized .env.example if needed.",
        "No .env or .env* ignore pattern found",
      );
    }

    // Scan each line for security issues
    lines.forEach((line, index) => {
      const n = index + 1;
      // Ignore comment-only lines
      if (/^\s*(?:\/\/|\/\*|\*|\*\/)/.test(line)) {
        return;
      }
      const patterns: Array<
        [RegExp, string, string, Finding["severity"], string, string]
      > = [
        [
          /\bAKIA[0-9A-Z]{16}\b/,
          "AWS access key ID",
          "AWS_ACCESS_KEY",
          "critical",
          "An AWS access key identifier appears in source code. If paired with a secret key, it may grant access to cloud resources.",
          "Revoke and rotate the key in AWS IAM. Store replacement credentials in a secure environment variable or secret manager.",
        ],
        [
          /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
          "GitHub access token",
          "GITHUB_TOKEN",
          "critical",
          "A GitHub token-like value appears in source code and may allow access to repositories or account resources.",
          "Revoke the token in GitHub settings and create a least-privilege replacement stored outside source control.",
        ],
        [
          /\bsk-[A-Za-z0-9_-]{20,}\b/,
          "OpenAI API key",
          "OPENAI_KEY",
          "critical",
          "An API-key-like value appears in source code and could be used to make API requests billed to the key owner.",
          "Revoke the exposed key, create a replacement, and load it from a server-side environment variable.",
        ],
        [
          /\bAIza[0-9A-Za-z_-]{35}\b/,
          "Google API key",
          "GOOGLE_API_KEY",
          "high",
          "A Google API key appears to be hardcoded in the project.",
          "Move the key into an environment variable and restrict it using Google Cloud API key restrictions.",
        ],

        [
          /\b(?:sk_live|rk_live)_[A-Za-z0-9]{16,}\b/,
          "Stripe live secret key",
          "STRIPE_LIVE_SECRET",
          "critical",
          "A Stripe live secret key appears to be hardcoded in the project.",
          "Revoke and rotate the exposed key in Stripe, then load the replacement from an environment variable.",
        ],

        [
          /\b(?:sk_test|rk_test)_[A-Za-z0-9]{16,}\b/,
          "Stripe test secret key",
          "STRIPE_TEST_SECRET",
          "medium",
          "A Stripe test secret key appears to be hardcoded in the project.",
          "Move the key into an environment variable and avoid including it in shared project files.",
        ],

        [
          /\b(?:xox[baprs]-|xapp-)[A-Za-z0-9-]{10,}\b/,
          "Slack access token",
          "SLACK_TOKEN",
          "high",
          "A Slack access token appears to be hardcoded in the project.",
          "Revoke and rotate the exposed token, then store the replacement securely in an environment variable.",
        ],
        [
          /(?:DATABASE_URL|DB_URL)\s*=\s*["']?(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s/]+:[^@\s/]+@[^"'\s]+/i,
          "Database connection credentials",
          "DATABASE_CREDENTIALS",
          "critical",
          "A database connection string containing a username and password was found in the project.",
          "Rotate the exposed database password and store the connection string in a secure server-side environment variable or secret manager.",
        ],
        [
          /\b(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*=\s*["']?(?!your[_-]|example|changeme|xxx)[^\s"'#]{8,}/i,
          "Hardcoded database password",
          "DATABASE_PASSWORD",
          "critical",
          "A hardcoded database password was found in the project.",
          "Change the exposed password and load it from a secure environment variable or secret manager.",
        ],
        [
          /\b(?:JWT_SECRET|JWT_SIGNING_SECRET|JWT_PRIVATE_KEY)\s*=\s*["']?(?!your[_-]|example|changeme|xxx)[A-Za-z0-9._~+/=-]{12,}["']?/i,
          "Hardcoded JWT signing secret",
          "JWT_SECRET",
          "critical",
          "A JWT signing secret or private-key reference appears to be hardcoded in the project.",
          "Rotate the exposed signing secret, invalidate affected tokens where appropriate, and store the replacement securely on the server.",
        ],

        [
          /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/,
          "Private key block",
          "PRIVATE_KEY",
          "critical",
          "A private cryptographic key block appears in the project. Anyone who obtains it may impersonate its owner.",
          "Treat the key as compromised. Revoke or replace it, and keep private keys in a protected secret store.",
        ],
        [
          /["']?\.(?:read|write)["']?\s*:\s*["']?true["']?/i,
          "Firebase rules allow unrestricted access",
          "FIREBASE_OPEN_RULES",
          "high",
          "Firebase Realtime Database rules allow read or write access without authentication.",
          "Require authenticated users and enforce ownership or role-based conditions. Test rules with the Firebase emulator.",
        ],
        [
          /\ballow\s+(?:read|write|read\s*,\s*write|write\s*,\s*read)\s*:\s*\(?\s*true\s*\)?\s*;/i,
          "Firebase rules allow unrestricted access",
          "FIREBASE_OPEN_RULES",
          "high",
          "Cloud Firestore rules allow access without checking user identity or permissions.",
          "Require authenticated users and enforce ownership or role-based conditions. Test rules with the Firebase emulator.",
        ],
        [
          /service_role/i,
          "Supabase service-role reference",
          "SUPABASE_SERVICE_ROLE",
          "medium",
          "A service-role reference was found. If the associated secret key is exposed to clients, it can bypass row-level security.",
          "Keep the service-role key on trusted server-side code only. Never prefix it with NEXT_PUBLIC_.",
        ],
        [
          /\b(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["'][^"']*["']\s*\+\s*[A-Za-z_$][\w.$]*)/i,
          "Potential SQL injection",
          "SQL_INJECTION",
          "high",
          "A SQL execution method appears to use dynamically constructed query text. If user-controlled input is included, this may allow SQL injection.",
          "Use parameterized queries or prepared statements. Never concatenate user-controlled input directly into SQL statements.",
        ],
        [
          /\b(?:child_process\.)?(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["'][^"']*["']\s*\+\s*[A-Za-z_$][\w.$]*)/i,
          "Potential command injection",
          "COMMAND_INJECTION",
          "high",
          "A shell command appears to be constructed using dynamic input. If that input is user-controlled, an attacker may execute unintended system commands.",
          "Avoid constructing shell commands from user input. Use safe process APIs with separate arguments and validate all input.",
        ],
        [
          /\beval\s*\(\s*(?:[A-Za-z_$][\w.$]*|[^)]*(?:\$\{[^}]+\}|\+\s*[A-Za-z_$][\w.$]*))[^)]*\)/i,
          "Potential unsafe dynamic code execution",
          "UNSAFE_EVAL",
          "high",
          "The eval() function appears to execute dynamically supplied code. If the input is untrusted, an attacker may execute arbitrary JavaScript.",
          "Avoid eval(). Use safer alternatives such as JSON.parse() for JSON data or explicit functions for supported operations.",
        ],
        [
          /(?:Access-Control-Allow-Origin\s*[:=]\s*["']\*["']|\borigin\s*:\s*["']\*["'])/i,
          "Potentially permissive CORS configuration",
          "CORS_WILDCARD",
          "high",
          "A CORS configuration appears to allow requests from any origin. This may expose sensitive resources if credentials or sensitive endpoints are involved.",
          "Restrict allowed origins to trusted domains. Avoid wildcard origins for sensitive APIs.",
        ],
        [
          /\b(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*["'`]http:\/\/(?!localhost\b|127(?:\.\d{1,3}){3}\b)[^"'`]+["'`]/i,
          "Insecure HTTP request",
          "INSECURE_HTTP",
          "medium",
          "An application request appears to use unencrypted HTTP instead of HTTPS. This may expose transmitted information to interception.",
          "Use HTTPS endpoints for network communication, especially when transmitting sensitive information.",
        ],
        [
          /\b(?:DEBUG|debug)\s*[:=]\s*(?:true|1)\b/,
          "Debug mode enabled",
          "DEBUG_ENABLED",
          "medium",
          "A debug configuration appears to be enabled. Exposed debug information may reveal application internals or sensitive details.",
          "Disable debug mode in production and use environment-specific configuration.",
        ],
        [
          /(?:createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)[^;\n]{0,160}\b(?:password|passwd|pwd)\b|\b(?:md5|sha1)\s*\(\s*(?:password|passwd|pwd)\b)/i,
          "Weak password hashing algorithm",
          "WEAK_PASSWORD_HASH",
          "high",
          "MD5 and SHA-1 are outdated hashing algorithms and are unsuitable for securely storing passwords.",
          "Use a password-hashing algorithm designed for password storage, such as Argon2id, bcrypt, or scrypt.",
        ],
        [
          /\b(?:SESSION_SECRET|AUTH_SECRET|COOKIE_SECRET|ACCESS_TOKEN_SECRET|REFRESH_TOKEN_SECRET|PASSWORD_RESET_SECRET)\s*[:=]\s*(?!\s*(?:process\.env|import\.meta\.env|env\.))(?!(?:["']?)(?:your[_-]|example|changeme|xxx))["']?[A-Za-z0-9._~+/=-]{12,}["']?/i,
          "Hardcoded authentication secret",
          "AUTH_SECRET",
          "critical",
          "An authentication or session secret appears to be hardcoded in the project.",
          "Rotate the exposed secret and store its replacement in a secure environment variable or secret manager.",
        ],
        [
          /(?:cookie|session)[^;\n]{0,120}(?:httpOnly|secure)\s*:\s*false|(?:httpOnly|secure)\s*:\s*false[^;\n]{0,120}(?:cookie|session)/i,
          "Insecure cookie configuration",
          "INSECURE_COOKIE",
          "high",
          "A cookie or session configuration appears to disable an important security protection.",
          "Enable HttpOnly and Secure for authentication cookies, and configure an appropriate SameSite policy.",
        ],
      ];

      for (const [regex, title, rule, severity, why, fix] of patterns) {
        const match = line.match(regex);

        if (match) {
          let evidence = line.trim();

          if (rule === "FIREBASE_OPEN_RULES") {
            evidence = "Unrestricted Firebase rule detected (value hidden)";
          } else if (rule === "PRIVATE_KEY") {
            evidence = "Private key block detected (key contents hidden)";
          } else {
            evidence = line
              .replace(match[0], redact(match[0]))
              .trim()
              .slice(0, 180);
          }

          add(findings, file, rule, title, severity, n, why, fix, evidence);
        }
      }

      // Generic high-entropy secret detection
      const genericMatch = line.match(
        /\b([A-Z0-9_]*(?:SECRET|TOKEN|API_KEY|ACCESS_KEY|PASSWORD)[A-Z0-9_]*)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{20,})["']?/i,
      );

      const alreadyDetected = patterns.some(([regex]) => regex.test(line));

      if (
        genericMatch &&
        !alreadyDetected &&
        !/^(your[_-]|example|changeme|xxx|process\.env|import\.meta\.env|env\.)/i.test(
          genericMatch[2],
        ) &&
        hasHighEntropy(genericMatch[2])
      ) {
        add(
          findings,
          file,
          "GENERIC_SECRET",
          "Potential hardcoded secret",
          "critical",
          n,
          "A high-entropy value assigned to a credential-related variable was found.",
          "Verify whether this is a real credential. If exposed, rotate it and store it in a secure secret manager.",
          `${genericMatch[1]}=${redact(genericMatch[2])}`,
        );
      }
    });
    // Weak password hashing detection
    const weakHashRegex =
      /(?:createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)[\s\S]{0,160}\.update\s*\(\s*(?:password|passwd|pwd)\b|\b(?:md5|sha1)\s*\(\s*(?:password|passwd|pwd)\b)/i;

    const weakHashMatch = file.text.match(weakHashRegex);
    if (weakHashMatch) {
      const hashLine = file.text
        .slice(0, weakHashMatch.index ?? 0)
        .split(/\r?\n/).length;

      add(
        findings,
        file,
        "WEAK_PASSWORD_HASH",
        "Weak password hashing algorithm",
        "high",
        hashLine,
        "MD5 and SHA-1 are outdated hashing algorithms and are unsuitable for securely storing passwords.",
        "Use a password-hashing algorithm designed for password storage, such as Argon2id, bcrypt, or scrypt.",
        "MD5/SHA-1 password hashing detected (value hidden)",
      );
    }
    // SQL and Supabase checks
    if (file.path.endsWith(".sql")) {
      const sql = file.text;

      const tables = [
        ...sql.matchAll(
          /create\s+table\s+(?:if\s+not\s+exists\s+)?["']?([\w.]+)["']?/gi,
        ),
      ].map((m) => m[1]);

      for (const table of tables) {
        const escaped = table.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

        const hasRls = new RegExp(
          `alter\\s+table\\s+(?:public\\.)?${escaped}\\s+enable\\s+row\\s+level\\s+security`,
          "i",
        ).test(sql);

        if (!hasRls) {
          add(
            findings,
            file,
            "SUPABASE_RLS_MISSING",
            `Table ${table} may not enable row-level security`,
            "high",
            1,
            "A table declaration was found without a matching ENABLE ROW LEVEL SECURITY statement in this SQL file.",
            `Enable row-level security for ${table}, then create policies that restrict rows by authenticated user or role.`,
            `CREATE TABLE ${table}`,
          );
        }
      }

      if (/using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)/i.test(sql)) {
        add(
          findings,
          file,
          "SUPABASE_OPEN_POLICY",
          "Supabase policy permits unrestricted access",
          "high",
          1,
          "A policy condition using true may allow all users to access or modify rows.",
          "Replace unconditional policies with ownership checks such as auth.uid() = user_id, where appropriate.",
          "Policy contains USING (true) or WITH CHECK (true)",
        );
      }
    }
  }

  // Remove duplicate Firebase findings from the same file
  const unique = [
    ...new Map(
      findings.map((f) => [
        f.ruleId === "FIREBASE_OPEN_RULES"
          ? `${f.ruleId}:${f.file}`
          : f.id,
        f,
      ])
    ).values(),
  ];

  // Calculate security score
  const deductions = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
  };

  const score = Math.max(
    0,
    100 - unique.reduce((sum, f) => sum + deductions[f.severity], 0)
  );

  return {
    findings: unique,
    score,
  };
}
