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
  reference:AdminReference; outcome:AdminOutcome|null; submissionOutcome:AdminOutcome|null; inFlight:boolean; revision:number;
}
export class AdminMutations {
  private records=new Map<string,AdminMutation>();
  get(scope:string){return this.records.get(scope);}
  restore(reference:AdminReference) {
    if(!this.records.has(reference.scope))this.records.set(reference.scope,{reference,outcome:null,submissionOutcome:null,inFlight:false,revision:0});
    return this.records.get(reference.scope)!;
  }
  begin(reference:AdminReference) {
    const current=this.records.get(reference.scope);
    if(current&&(current.inFlight||!current.outcome||current.outcome.kind==="uncertain"))throw Error("Check the earlier change before starting another");
    const record={reference,outcome:null,submissionOutcome:null,inFlight:true,revision:0};this.records.set(reference.scope,record);return record;
  }
  settle(reference:AdminReference,value:AdminOutcome,expectedRevision?:number) {
    const record=this.records.get(reference.scope);
    if(!record||record.reference.review_id!==reference.review_id||expectedRevision!==undefined&&record.revision!==expectedRevision)return false;
    const reply=value.reference;
    const matching=reply.review_id===reference.review_id&&reply.review_digest===reference.review_digest
      &&reply.scope===reference.scope&&reply.action===reference.action&&reply.enrollment_id===reference.enrollment_id
      &&reply.enrollment_digest===reference.enrollment_digest;
    const result:AdminOutcome=matching?value:{reference,kind:"uncertain",observed:null,detail:"The reply did not match this saved change. Check status without resending."};
    if(expectedRevision===undefined) {
      record.submissionOutcome=result;
      record.inFlight=false;
      // A later explicit state observation takes presentation precedence over
      // its older submission reply. Retain both without losing either result.
      if(record.revision===0)record.outcome=result;
    } else record.outcome=result;
    ++record.revision;return true;
  }
}
