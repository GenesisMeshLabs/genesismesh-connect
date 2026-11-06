import type {AdminOutcome,AdminReference} from "./host-admin-state";
/** Presentation can be abandoned; a submitted native mutation cannot. */
export class AdminPresentationSession {
  private generation=0;
  private active=false;
  open(){this.active=true;return ++this.generation;}
  close(){this.active=false;++this.generation;}
  token(){return this.generation;}
  current(token:number){return this.active&&token===this.generation;}
}
export interface AdminMutation {
  reference:AdminReference; outcome:AdminOutcome|null; submissionOutcome:AdminOutcome|null; inFlight:boolean;
  readbackRevision:number; readbackPending:boolean;
}
export function adminMutationPending(record:AdminMutation) {
  return record.inFlight||record.readbackPending||!record.outcome||record.outcome.kind==="uncertain";
}
function sameReference(a:AdminReference,b:AdminReference) {
  return a.review_id===b.review_id&&a.review_digest===b.review_digest&&a.scope===b.scope
    &&a.action===b.action&&a.enrollment_id===b.enrollment_id&&a.enrollment_digest===b.enrollment_digest;
}
export class AdminMutations {
  private records=new Map<string,AdminMutation>();
  get(scope:string){return this.records.get(scope);}
  restore(reference:AdminReference) {
    if(!this.records.has(reference.scope))this.records.set(reference.scope,{reference,outcome:null,submissionOutcome:null,inFlight:false,readbackRevision:0,readbackPending:false});
    return this.records.get(reference.scope)!;
  }
  begin(reference:AdminReference) {
    const current=this.records.get(reference.scope);
    if(current&&adminMutationPending(current))throw Error("Check the earlier change before starting another");
    const record={reference,outcome:null,submissionOutcome:null,inFlight:true,readbackRevision:0,readbackPending:false};this.records.set(reference.scope,record);return record;
  }
  beginReadback(reference:AdminReference) {
    const record=this.records.get(reference.scope);
    if(!record||!sameReference(record.reference,reference))throw Error("Check the original saved change in this network");
    record.readbackPending=true;
    return ++record.readbackRevision;
  }
  settle(reference:AdminReference,value:AdminOutcome,readbackRevision?:number) {
    const record=this.records.get(reference.scope);
    if(!record||!sameReference(record.reference,reference)||readbackRevision!==undefined&&(!record.readbackPending||record.readbackRevision!==readbackRevision))return false;
    const matching=sameReference(value.reference,reference);
    const result:AdminOutcome=matching?value:{reference,kind:"uncertain",observed:null,detail:"The reply did not match this saved change. Check status without resending."};
    if(readbackRevision===undefined) {
      record.submissionOutcome=result;
      record.inFlight=false;
      // A requested readback is newer than this submission, regardless of
      // reply order. Retain the submission without invalidating that readback.
      if(record.readbackRevision===0)record.outcome=result;
    } else {record.outcome=result;record.readbackPending=false;}
    return true;
  }
}
