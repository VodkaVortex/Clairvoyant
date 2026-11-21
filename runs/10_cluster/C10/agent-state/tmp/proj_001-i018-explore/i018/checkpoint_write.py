import json, os, sys

ckpt_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/agent-state/checkpoints/i018.json"

def write_checkpoint(data):
    tmp = ckpt_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, ckpt_path)

if __name__ == "__main__":
    initial = {
        "intent_id": "i018",
        "branch": "terminator-write-off-by-one",
        "snapshot": "s01",
        "status": "in_progress",
        "phase": "initial",
        "plan": [
            "1. Resolve versal_edac.c inject_data_ue_store (char buf[6], min_t clamp, buf[len]='\\0') with line-level bound analysis",
            "2. Examine zynqmp_edac.c inject_ue_write for identical pattern",
            "3. Sweep s01 write interfaces (debugfs .write, sysfs/configfs ->store with own copy, proc .proc_write, scsi ->write_info, char-dev/ioctl writers, module_param handlers) for clamp-without-minus-1 then buf[len]=0 sites",
            "4. Reject candidates with concrete evidence (count > sizeof(buf)-1 enforced, or len+1 allocation)",
            "5. Write final artifact findings/i018.json"
        ],
        "candidates": [],
        "notes": "initial checkpoint before first search"
    }
    write_checkpoint(initial)
    print("checkpoint written:", ckpt_path)
