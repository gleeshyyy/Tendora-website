(() => {
'use strict';
const ENGINE_BASE='https://cdn.jsdelivr.net/npm/@wasm-zoo/ghostscript@0.7.2/';
const $=id=>document.getElementById(id);
const picker=$('pdf-file'),fileCard=$('file-card'),fileName=$('file-name'),fileSize=$('file-size'),status=$('status'),button=$('compress'),resultBox=$('result'),resultDetail=$('result-detail'),downloadLink=$('download');
let selectedFile=null,downloadUrl=null,enginePromise=null,busy=false;
function size(n){return n<1048576?(n/1024).toFixed(1)+' KB':(n/1048576).toFixed(2)+' MB'}
function say(message,error=false){status.textContent=message;status.classList.toggle('error',error)}
function clearResult(){resultBox.classList.remove('show');if(downloadUrl){URL.revokeObjectURL(downloadUrl);downloadUrl=null}downloadLink.removeAttribute('href')}
function selectFile(file){if(!file)return;selectedFile=file;fileName.textContent=file.name||'Selected PDF';fileSize.textContent=size(file.size);fileCard.classList.add('show');button.disabled=false;clearResult();say('PDF selected. Ready to compress.')}
function syncPicker(){const f=picker.files&&picker.files.length?picker.files[0]:null;if(f&&f!==selectedFile)selectFile(f)}
picker.addEventListener('change',syncPicker);
picker.addEventListener('input',syncPicker);
document.addEventListener('change',e=>{if(e.target===picker)syncPicker()},true);
window.addEventListener('focus',()=>setTimeout(syncPicker,250));
window.addEventListener('pageshow',()=>setTimeout(syncPicker,250));
document.addEventListener('visibilitychange',()=>{if(!document.hidden)setTimeout(syncPicker,250)});
function loadEngine(){
 if(window.WasmZooGhostscript&&typeof window.WasmZooGhostscript.loadHosted==='function')return Promise.resolve();
 if(enginePromise)return enginePromise;
 enginePromise=new Promise((resolve,reject)=>{
  const s=document.createElement('script');s.src=ENGINE_BASE+'browser-ghostscript.js';s.crossOrigin='anonymous';
  s.onload=()=>window.WasmZooGhostscript&&typeof window.WasmZooGhostscript.loadHosted==='function'?resolve():reject(new Error('Ghostscript browser runtime did not initialize.'));
  s.onerror=()=>reject(new Error('Could not download the compression engine. Check your internet connection.'));
  document.head.appendChild(s);
 }).catch(e=>{enginePromise=null;throw e});
 return enginePromise;
}
function argsFor(level){
 const p={screen:{name:'screen',dpi:72},ebook:{name:'ebook',dpi:150},printer:{name:'printer',dpi:300}}[level]||{name:'ebook',dpi:150};
 return ['-dSAFER','-dBATCH','-dNOPAUSE','-dQUIET','-sDEVICE=pdfwrite','-dCompatibilityLevel=1.4','-dPDFSETTINGS=/'+p.name,'-dDetectDuplicateImages=true','-dCompressFonts=true','-dSubsetFonts=true','-dDownsampleColorImages=true','-dColorImageDownsampleType=/Bicubic','-dColorImageResolution='+p.dpi,'-dDownsampleGrayImages=true','-dGrayImageDownsampleType=/Bicubic','-dGrayImageResolution='+p.dpi,'-dDownsampleMonoImages=true','-dMonoImageResolution='+Math.max(150,p.dpi),'-sOutputFile=/output/compressed.pdf','/input/original.pdf'];
}
button.addEventListener('click',async()=>{
 if(busy)return;if(!selectedFile){say('Select a PDF file first.',true);return}
 busy=true;button.disabled=true;clearResult();say('Preparing compression…');let runner=null;
 try{
  const head=new TextDecoder().decode(new Uint8Array(await selectedFile.slice(0,1024).arrayBuffer()));
  if(!head.includes('%PDF-'))throw new Error('This file does not appear to be a valid PDF.');
  await loadEngine();say('Loading Ghostscript WebAssembly. First use may take longer…');
  runner=window.WasmZooGhostscript.loadHosted({baseUrl:ENGINE_BASE});
  const result=await runner.exec(argsFor($('quality').value),{files:[{name:'/input/original.pdf',data:selectedFile}],dirs:['/input','/output'],outputs:['/output/compressed.pdf'],timeoutMs:600000});
  const output=result.files.find(f=>f.name==='/output/compressed.pdf');
  if(!output||!output.data||output.data.byteLength<8)throw new Error('The compression engine did not produce a PDF.');
  const outSig=new TextDecoder().decode(output.data.slice(0,1024));
  if(!outSig.includes('%PDF-'))throw new Error('The compression engine returned an invalid PDF.');
  const blob=new Blob([output.data],{type:'application/pdf'});downloadUrl=URL.createObjectURL(blob);
  const diff=selectedFile.size-blob.size,pct=(Math.abs(diff)/selectedFile.size*100).toFixed(1);
  const result=diff>0?pct+'% smaller':diff<0?pct+'% larger':'about the same size';
  resultDetail.textContent='Original: '+size(selectedFile.size)+' · Compressed: '+size(blob.size)+' · Result: '+result+(diff<=0?'. This PDF did not become smaller at this quality level.':'.');
  downloadLink.href=downloadUrl;downloadLink.download=(selectedFile.name||'document.pdf').replace(/\.pdf$/i,'')+'-compressed.pdf';
  resultBox.classList.add('show');say('Compression finished.');
 }catch(e){console.error('Tendora PDF compressor:',e);say(e&&e.message?e.message:'Compression failed. Try another PDF.',true)}
 finally{if(runner&&runner.dispose)runner.dispose();busy=false;button.disabled=!selectedFile}
});
window.addEventListener('beforeunload',()=>{if(downloadUrl)URL.revokeObjectURL(downloadUrl)});
})();