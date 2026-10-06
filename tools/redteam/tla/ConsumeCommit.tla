---- MODULE ConsumeCommit ----
(*** The one-shot consume and commit transition of the challenge
    record, the atomicity boundary change.md 3.7.2 names for model
    checking ("single-use consume ... each transition's atomicity
    boundary is documented and model-checked").

    The state machine of one challenge record, in scalar form (the
    model tracks the single nonce the consume boundary owns):

      "none"     no record exists
      "Issued"   the signed record is stored, pending redemption
      "Consumed" the atomic consume retired the record once
      the commit count carries the accepted redemption

    Transitions:

      Issue         no record -> Issued (the issuer's create-or-get)
      Consume       Issued -> Consumed, exactly once (one-shot)
      ConsumeRetry  a consume attempt on a retired or absent record:
                    the store answers record_not_found, the refusal
                    counter climbs, nothing else changes
      VerifyCommit  Consumed -> the commit counter steps to 1 (the
                    wire answers ok once)
      Replay        a verify attempt on a non-consumed record is
                    refused the same way

    The invariants the release gate checks (zero violations):

      RecordState    the record is always in its three-state domain
      ConsumedByOK   the consuming client is a real client or none
      OneShot        a Consumed record always names exactly one client
      NoDoubleCommit the commit count never exceeds one
      NoAcceptWithoutConsume  an accepted commit implies the record
                     left Issued through exactly one Consume first

    The failure schedule the spec models: a client may retry the
    consume after an ambiguous timeout (the partial-batch retry shape)
    and a second worker may race the consume; the atomicity boundary
    makes both safe. ***)

EXTENDS Naturals

CONSTANT Clients
CONSTANT MaxRefusals

VARIABLES
    \* the record's lifecycle: "none", "Issued" or "Consumed"
    record,
    \* the client that consumed the record, 0 when none
    consumedBy,
    \* the accepted-verify count (the wire's ok answers)
    commits,
    \* the refused-replay count
    refusals

Init ==
    /\ record = "none"
    /\ consumedBy = 0
    /\ commits = 0
    /\ refusals = 0

Issue(client) ==
    /\ record = "none"
    /\ record' = "Issued"
    /\ UNCHANGED <<consumedBy, commits, refusals>>

(* The atomic consume: the read-modify-retire transition. Two racing
   clients may both attempt it; the guard makes exactly one win, which
   is the atomicity boundary the checker pins. *)
Consume(client) ==
    /\ record = "Issued"
    /\ record' = "Consumed"
    /\ consumedBy' = client
    /\ UNCHANGED <<commits, refusals>>

(* A consume retry after an ambiguous timeout: the store answers
   record_not_found and nothing changes but the refusal counter. The
   retry schedule is bounded (CONSTANT MaxRefusals), the partial-batch
   retry shape of the store's documented idempotency contract. *)
ConsumeRetry(client) ==
    /\ record # "Issued"
    /\ refusals < MaxRefusals
    /\ refusals' = refusals + 1
    /\ UNCHANGED <<record, consumedBy, commits>>

(* The commit after a verified redemption: the wire answers ok once. *)
VerifyCommit(client) ==
    /\ record = "Consumed"
    /\ consumedBy = client
    /\ commits < 1
    /\ commits' = commits + 1
    /\ UNCHANGED <<record, consumedBy, refusals>>

(* The replay: a verify on a record that is not in the Consumed
   state is refused; the state does not change. The same bounded
   schedule applies. *)
Replay(client) ==
    /\ record # "Consumed"
    /\ refusals < MaxRefusals
    /\ refusals' = refusals + 1
    /\ UNCHANGED <<record, consumedBy, commits>>

Next ==
    \/ \E c \in Clients: Issue(c)
    \/ \E c \in Clients: Consume(c)
    \/ \E c \in Clients: ConsumeRetry(c)
    \/ \E c \in Clients: VerifyCommit(c)
    \/ \E c \in Clients: Replay(c)

Spec == Init /\ [][Next]_<<record, consumedBy, commits, refusals>>

RecordState == record \in {"none", "Issued", "Consumed"}

ConsumedByOK ==
    \/ consumedBy = 0
    \/ consumedBy \in Clients

OneShot ==
    record = "Consumed" => consumedBy # 0

NoDoubleCommit ==
    commits <= 1

NoAcceptWithoutConsume ==
    (commits = 1) => (record # "Issued" /\ consumedBy # 0)

THEOREM Spec => [](RecordState /\ ConsumedByOK /\ OneShot /\
                   NoDoubleCommit /\ NoAcceptWithoutConsume)

=============================================================================
