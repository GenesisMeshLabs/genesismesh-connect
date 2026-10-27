"""Connect's inherited-pipe owner sidecar entry point. No TCP admin listener."""
import argparse
import json
import sys
import os

from owner import Owner, Refused


def main():
    if os.name != "nt":
        os.umask(0o077)
    parser=argparse.ArgumentParser()
    parser.add_argument("--state",required=True)
    args=parser.parse_args()
    owner=Owner(args.state)
    print(json.dumps({"protocol":1}),flush=True)
    try:
        while True:
            line=sys.stdin.buffer.readline(32769)
            if not line: break
            if len(line)>32768: break
            try:
                request=json.loads(line)
                op=request.get("op")
                if op=="create" and set(request)=={"op","name"}: result=owner.create(request["name"])
                elif op=="open" and set(request)=={"op"}: result=owner.open()
                elif op=="attach" and set(request)=={"op","config"}: result=owner.attach(request["config"])
                elif op=="invite" and set(request)=={"op","node","host"} and type(request["host"]) is bool: result=owner.invite(request["node"],request["host"])
                elif op=="share" and set(request)=={"op","host","peer","collection"}: result=owner.share(request["host"],request["peer"],request["collection"])
                elif op=="share" and set(request)=={"op","host","peer","collection","subject"}: result=owner.share(request["host"],request["peer"],request["collection"],request["subject"])
                else: raise Refused("Unsupported network setup operation.")
                print(json.dumps({"ok":result}),flush=True)
            except Refused as error:
                print(json.dumps({"error":str(error)}),flush=True)
            except Exception:
                # Never reflect key data, invitations or filesystem contents.
                print(json.dumps({"error":"The local network operation could not be completed. Your existing identity has been preserved."}),flush=True)
    finally:
        owner.close()


if __name__=="__main__": main()
