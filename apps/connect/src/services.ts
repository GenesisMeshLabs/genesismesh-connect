import { invoke, isTauri } from "@tauri-apps/api/core";
import { el } from "./ui";
import { friendlyProblem, type HomeStatus, type HomeSpace } from "./home-state";
import { setupAccessEditor } from "./access-editor";
interface Connection { id:string; name:string; kind:HomeSpace["kind"]; address:string; url:string|null; problem:string|null }
export function setupServices(getStatus:()=>HomeStatus|null, refresh:()=>Promise<void>, message:(s:string)=>void) {
  const access=setupAccessEditor(getStatus,refresh,message);
  let polling=false;
  async function connections() {
    if(polling||!isTauri())return;polling=true;
    try {
      const items=(await invoke<Connection[]>("service_connections"))||[];
      const list=el("open-service-list"), stamp=JSON.stringify(items);
      el("open-services").hidden=!items.length;
      if(list.dataset.state===stamp)return;list.dataset.state=stamp;list.replaceChildren();
      for(const item of items) {
        const row=document.createElement("div");row.className="service-connection";
        const title=document.createElement("h3");title.textContent=item.name;
        const description=document.createElement("p");description.textContent=item.problem ? friendlyProblem(item.problem) : item.kind==="web" ? "Ready to open in the browser. The service’s own login may be required." : "Use this address in your client app. The service’s own login still applies.";
        const address=document.createElement("code");address.textContent=item.address;
        const actions=document.createElement("div");actions.className="button-row";
        const copy=document.createElement("button");copy.className="secondary";copy.textContent="Copy address";
        copy.onclick=()=>void navigator.clipboard.writeText(item.address).then(()=>message("Connection address copied."),()=>message("Select and copy the address shown above."));actions.append(copy);
        if(item.url){const open=document.createElement("button");open.textContent="Open app";open.onclick=()=>void invoke("launch_service",{id:item.id}).catch(e=>message(friendlyProblem(String(e))));actions.append(open);}
        const close=document.createElement("button");close.className="secondary";close.textContent="Close connection";
        close.onclick=()=>void invoke("close_service",{id:item.id}).then(connections,e=>message(friendlyProblem(String(e))));actions.append(close);
        row.append(title,description,address,actions);list.append(row);
      }
    }catch{/* An unavailable status read does not claim that a connection is closed. */}
    finally{polling=false;}
  }
  setInterval(()=>{if(!document.hidden)void connections();},2000);
  return {access,open:async(space:HomeSpace)=>{
    await invoke<Connection>("open_service",{id:space.id});await connections();
    if(space.kind==="web")await invoke("launch_service",{id:space.id});
    else el("open-services").scrollIntoView({behavior:"smooth",block:"start"});
  }};
}
