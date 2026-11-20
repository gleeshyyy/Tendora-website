/* Tendora background-remover model preloader.
   Warms the browser cache after the visitor has been on the homepage for a while.
   Skips reduced-data and very slow connections. */
(()=> {
 const connection=navigator.connection||navigator.mozConnection||navigator.webkitConnection;
 if(connection?.saveData||["slow-2g","2g"].includes(connection?.effectiveType))return;
 const start=async()=>{
  if(document.hidden||!("caches" in window))return;
  try{
   const {pipeline,env}=await import("https://cdn.jsdelivr.net/npm/@huggingface/transformers@3.8.1");
   env.allowLocalModels=false;env.allowRemoteModels=true;env.useBrowserCache=true;
   env.remoteHost=location.origin+"/hf-models";
   env.remotePathTemplate="{model}/resolve/{revision}";
   let device="wasm";
   if(navigator.gpu){try{const adapter=await navigator.gpu.requestAdapter();if(adapter)device="webgpu"}catch{}}
   try{if(device==="webgpu")await pipeline("image-segmentation","d30social/ormbg-ortweb",{device,dtype:"fp16"});else await pipeline("background-removal","Orangebot/ormbg-ONNX",{device:"wasm",dtype:"uint8"})}
   catch(error){if(device!=="webgpu")throw error;console.warn("GPU preload unavailable; warming the CPU-compatible model instead.",error);await pipeline("background-removal","Orangebot/ormbg-ONNX",{device:"wasm",dtype:"uint8"})}
   console.info("Tendora background-remover model is cached for this browser.");
  }catch(error){console.warn("Tendora background model preloading was deferred or failed:",error)}
 };
 const schedule=()=>{if("requestIdleCallback" in window)requestIdleCallback(start,{timeout:15000});else setTimeout(start,12000)};
 if(document.readyState==="complete")schedule();else window.addEventListener("load",schedule,{once:true});
})();
