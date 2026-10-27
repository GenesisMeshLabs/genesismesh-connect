import { invoke, isTauri } from "@tauri-apps/api/core";
import { el, input } from "./ui";
import { isService, friendlyProblem, formatBytes, type HomeStatus, type HomeSpace } from "./home-state";
interface AccessPolicy { version:number; recipients:string[]; expires_at:string|null; max_bytes:number; max_seconds:number; extra_gates:unknown[] }
interface Connection { id:string; name:string; kind:HomeSpace["kind"]; address:string; url:string|null; problem:string|null }
export function setupServices(getStatus:()=>HomeStatus|null, refresh:()=>Promise<void>, message:(s:string)=>void) {
  const dialog=el<HTMLDialogElement>("access-dialog");
  let editing:HomeSpace|null=null, policy:AccessPolicy|null=null, saving=false, polling=false, originalExpiry="";
  function problem(value:string) {el("access-problem").textContent=value;el("access-problem").hidden=!value;}
  function selectCurrent(id:string,value:number,label:string) {
    const select=el<HTMLSelectElement>(id);
    select.querySelectorAll('[data-current]').forEach(o=>o.remove());
    if (![...select.options].some(o=>o.value===String(value))) {const option=new Option(label,String(value));option.dataset.current="true";select.add(option);}
    select.value=String(value);
  }
  async function access(space:HomeSpace) {
    const result=await invoke<AccessPolicy>("get_access_policy",{id:space.id});
    policy=result;editing=space;problem("");
    el("access-title").textContent=`Access to ${space.name}`;
    el("access-version").textContent=`Policy version ${result.version} · Changes are enforced by your network authority.`;
    const list=el("access-devices");list.replaceChildren();
    const devices=new Map(getStatus()?.devices.map(d=>[d.id,d.name]) || []);
    // Retain existing grants even if the current member list is temporarily stale.
    for(const id of result.recipients) if(!devices.has(id)) devices.set(id,"Previously allowed device (refresh Devices to identify)");
    for(const [id,name] of devices) {
      const label=document.createElement("label"), box=document.createElement("input");
      box.type="checkbox";box.name="access-recipient";box.value=id;box.checked=result.recipients.includes(id);
      label.append(box,document.createTextNode(name));list.append(label);
    }
    if(result.expires_at) {
      const date=new Date(result.expires_at);date.setMinutes(date.getMinutes()-date.getTimezoneOffset());input("access-expiry").value=date.toISOString().slice(0,16);
    } else input("access-expiry").value="";
    originalExpiry=input("access-expiry").value;
    selectCurrent("access-size",result.max_bytes,`Current limit: ${formatBytes(result.max_bytes)}`);
    selectCurrent("access-duration",result.max_seconds,`Current limit: ${result.max_seconds} seconds`);
    el("access-duration-field").hidden=!isService(space);
    input("access-extra").value=JSON.stringify(result.extra_gates,null,2);
    dialog.showModal();
  }
  el("access-close").addEventListener("click",()=>{if(!saving)dialog.close();});
  dialog.addEventListener("cancel",e=>{if(saving)e.preventDefault();});
  el("access-form").addEventListener("submit",async e=>{
    e.preventDefault();if(saving||!editing||!policy)return;problem("");
    const recipients=[...dialog.querySelectorAll<HTMLInputElement>('input[name="access-recipient"]:checked')].map(b=>b.value);
    if(!recipients.length){problem("Choose at least one device, or use Stop sharing to close access for everyone.");return;}
    let extra_gates:unknown;
    try{extra_gates=JSON.parse(input("access-extra").value);}catch{problem("Additional rules must be a valid JSON array.");return;}
    if(!Array.isArray(extra_gates)){problem("Additional rules must be a JSON array.");return;}
    let expires_at:string|null=null;
    if(input("access-expiry").value){const date=new Date(input("access-expiry").value);if(!Number.isFinite(date.getTime())||date.getTime()<=Date.now()){problem("Choose a future expiry date.");return;}expires_at=date.toISOString();}
    if(input("access-expiry").value===originalExpiry) expires_at=policy.expires_at;
    saving=true;el<HTMLButtonElement>("access-save").disabled=true;
    try {
      await invoke("update_access_policy",{id:editing.id,settings:{...policy,recipients,expires_at,max_bytes:Number(el<HTMLSelectElement>("access-size").value),max_seconds:Number(el<HTMLSelectElement>("access-duration").value),extra_gates}});
      dialog.close();message("Access policy saved. New connections use the updated rules; open service sessions recheck them within 10 seconds.");await refresh();
    }catch(error){problem(friendlyProblem(String(error)));}
    finally{saving=false;el<HTMLButtonElement>("access-save").disabled=false;}
  });
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
