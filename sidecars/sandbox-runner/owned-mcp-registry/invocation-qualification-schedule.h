#ifndef OWASP_AI_GOAT_INVOCATION_QUALIFICATION_SCHEDULE_H
#define OWASP_AI_GOAT_INVOCATION_QUALIFICATION_SCHEDULE_H
/* No runtime selector: only explicitly named qualification image builds define it. */
#ifdef OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE
#if OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE != 2 && OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE != 3
#error Invalid fixed qualification phase
#endif
static unsigned int qualification_ordinal=0;
static int qualification_paused=0;
static void qualification_start(void){qualification_ordinal++;}
static int qualification_hold(int phase,long now,long until,int cancelled){
 if(cancelled||now>=until||qualification_ordinal!=1||phase!=OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE)return 0;
 if(!qualification_paused){fprintf(stderr,"OWASP_AI_GOAT_ATTEST_QUAL paused phase=%d ordinal=1\n",phase);qualification_paused=1;}
 return 1;
}
static void qualification_admitted(int phase,int attested,long now,long until,long worker_deadline){
 if(qualification_ordinal==1)fprintf(stderr,"OWASP_AI_GOAT_ATTEST_QUAL admitted phase=%d ordinal=1 attested=%d releaseCount=%d deadlineValid=%d\n",phase,attested?1:0,phase>=3?1:0,now<until&&now<worker_deadline?1:0);
}
#define QUALIFICATION_START() qualification_start()
#define QUALIFICATION_HOLD(phase,now,until,cancelled) qualification_hold(phase,now,until,cancelled)
#define QUALIFICATION_ADMITTED(phase,attested,now,until,worker_deadline) qualification_admitted(phase,attested,now,until,worker_deadline)
#else
#define QUALIFICATION_START() ((void)0)
#define QUALIFICATION_HOLD(phase,now,until,cancelled) 0
#define QUALIFICATION_ADMITTED(phase,attested,now,until,worker_deadline) ((void)0)
#endif
#endif
