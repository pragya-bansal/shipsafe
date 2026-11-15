import { NextRequest, NextResponse } from "next/server";
import yauzl from "yauzl";
import { Readable } from "node:stream";
import { scanFiles, type ScannedFile } from "@/lib/scanner";

export const runtime = "nodejs";
const MAX_UPLOAD=20*1024*1024, MAX_ENTRIES=2000, MAX_TOTAL=80*1024*1024, MAX_FILE=1024*1024;
const SKIP_DIRS=["node_modules/",".git/",".next/","dist/","build/"];

function readZip(buffer: Buffer): Promise<{files:ScannedFile[];skipped:number}> {
  return new Promise((resolve,reject)=>{
    yauzl.fromBuffer(buffer,{lazyEntries:true,autoClose:true,decodeStrings:true},(err,zip)=>{
      if(err||!zip) return reject(new Error("The uploaded file is not a valid ZIP archive."));
      const files:ScannedFile[]=[]; let entries=0,total=0,skipped=0,done=false;
      const finish=(error?:Error)=>{if(done)return;done=true;try{zip.close();}catch{};error?reject(error):resolve({files,skipped});};
      zip.on("error",e=>finish(new Error("Could not safely read this ZIP archive.")));
      zip.on("entry",entry=>{
        entries++;
        if(entries>MAX_ENTRIES) return finish(new Error("ZIP contains too many entries (limit: 2,000)."));
        const name=entry.fileName.replace(/\\/g,"/");
        if(name.startsWith("/") || name.split("/").some((part: string) => part === "..")) return finish(new Error("ZIP contains an unsafe file path."));
        if(name.endsWith("/")) { zip.readEntry(); return; }
        if((entry.generalPurposeBitFlag & 1)!==0) return finish(new Error("Password-protected ZIP files are not supported."));
        if(SKIP_DIRS.some(d=>name.includes(d.trim()))) {skipped++;zip.readEntry();return;}
        if(entry.uncompressedSize>MAX_FILE) {skipped++;zip.readEntry();return;}
        total+=entry.uncompressedSize;
        if(total>MAX_TOTAL) return finish(new Error("ZIP expands beyond the 80 MB safety limit."));
        if(entry.uncompressedSize/Math.max(entry.compressedSize,1)>100) return finish(new Error("ZIP contains a suspiciously compressed file."));
        zip.openReadStream(entry,(streamErr,stream)=>{
          if(streamErr||!stream) return finish(new Error("Could not read a ZIP entry."));
          const chunks:Buffer[]=[];let size=0;let binary=false;
          stream.on("data",(chunk:Buffer)=>{size+=chunk.length;if(size>MAX_FILE){binary=true;stream.destroy();return;}chunks.push(chunk);});
          stream.on("error",()=>finish(new Error("Error while reading ZIP contents.")));
          stream.on("end",()=>{
            const data=Buffer.concat(chunks);
            if(binary || data.includes(0)) skipped++;
            else files.push({path:name,text:data.toString("utf8")});
            zip.readEntry();
          });
        });
      });
      zip.on("end",()=>finish());
      zip.readEntry();
    });
  });
}

export async function POST(request:NextRequest) {
  try {
    const form=await request.formData();
    const file=form.get("file");
    if(!(file instanceof File)) return NextResponse.json({error:"Choose a ZIP file first."},{status:400});
    if(file.size>MAX_UPLOAD) return NextResponse.json({error:"File is larger than the 20 MB upload limit."},{status:413});
    const buffer=Buffer.from(await file.arrayBuffer());
    if(buffer.length<4 || buffer[0]!==0x50 || buffer[1]!==0x4b) return NextResponse.json({error:"The selected file does not appear to be a ZIP archive."},{status:400});
    const {files,skipped}=await readZip(buffer);
    const result=scanFiles(files);
    return NextResponse.json({projectName:file.name.replace(/\.zip$/i,""),scannedFiles:files.length,skippedFiles:skipped,score:result.score,findings:result.findings});
  } catch(error) {
    const message=error instanceof Error?error.message:"Unable to scan this archive.";
    return NextResponse.json({error:message},{status:400});
  }
}
