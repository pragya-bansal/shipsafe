import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ShipSafe — Project Security Scanner",
  description: "Scan developer projects for exposed secrets and risky configurations.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
