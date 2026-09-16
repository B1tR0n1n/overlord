#!/usr/bin/env python3
"""OVERLORD skills — packaged know-how the agent can pull in when it fits.

A skill is a folder with a SKILL.md (front matter: name, description, an
optional `when`) and any supporting files. Two homes:

  project   <folder>/.overlord/skills/<name>/   part of the tree, so part of
            the transaction: an agent may write or edit one and the change
            is a reviewed diff like any other; it commits or rolls back with
            everything else.
  machine   ~/.overlord/skills/<name>/          installed by a person
            (`overlord skills add <path>`), offered to every conversation,
            capped by the policy rule "skills" for a folder.

The agent is told the catalogue (name + description) up front and loads a
skill with the `skill` tool only when the description fits the task — the
text is not in the prompt until then. Every load is a transcript event.

    overlord skills list [-t <dir>]        # what a conversation there would see
    overlord skills show <name>
    overlord skills add <path> [--name n]  # install a folder (or SKILL.md) machine-wide
    overlord skills new <name> [-t <dir>]  # scaffold one (in the folder with -t)
    overlord skills rm <name>
"""

import os
import re
import shutil

import overlord as core

SKILL_FILE = "SKILL.md"
PROJECT_DIR = os.path.join(".overlord", "skills")
MACHINE_DIR = os.path.join(core.OVERLORD_HOME, "skills")
FILE_CAP = 16_000           # chars of one skill file handed to the model
DESC_CAP = 300
MAX_SKILLS = 64
MAX_FILES = 40
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

SKILL_TOOL = {
    "name": "skill",
    "description": ("Load a skill from the catalogue in your instructions: returns its SKILL.md "
                    "(or one of its supporting files with `file`). Use it when a skill's "
                    "description fits the task; do not load skills you do not need."),
    "input_schema": {"type": "object",
                     "properties": {"name": {"type": "string"},
                                    "file": {"type": "string",
                                             "description": "a supporting file, relative to the skill"}},
                     "required": ["name"]},
}


class SkillError(core.OverlordError):
    pass


def check_name(name):
    if not _NAME_RE.match(name or ""):
        raise SkillError("error: skill names are 1-64 chars of a-z 0-9 . _ - (lowercase)")
    return name


def parse(text):
    """Front matter between --- lines (key: value), then the body."""
    meta, body = {}, text
    m = re.match(r"^---[ \t]*\n(.*?)\n---[ \t]*\n?", text, re.S)
    if m:
        for line in m.group(1).splitlines():
            k, sep, v = line.partition(":")
            if sep and k.strip():
                meta[k.strip().lower()] = v.strip().strip("\"'")
        body = text[m.end():]
    return meta, body


def _entry(path, source, name):
    try:
        with open(os.path.join(path, SKILL_FILE), encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    meta, body = parse(text)
    files = []
    for root, dirs, names in os.walk(path):
        dirs[:] = [d for d in sorted(dirs) if not d.startswith(".")]
        for n in sorted(names):
            rel = os.path.relpath(os.path.join(root, n), path)
            if rel != SKILL_FILE and not n.startswith("."):
                files.append(rel)
            if len(files) >= MAX_FILES:
                break
    desc = " ".join((meta.get("description") or body.strip().split("\n", 1)[0] or "").split())
    return {"name": name, "source": source, "path": path,
            "description": desc[:DESC_CAP], "when": meta.get("when", "")[:DESC_CAP],
            "files": files, "chars": len(text)}


def scan(base, source):
    out = []
    if not os.path.isdir(base):
        return out
    for n in sorted(os.listdir(base)):
        if _NAME_RE.match(n) and os.path.isfile(os.path.join(base, n, SKILL_FILE)):
            e = _entry(os.path.join(base, n), source, n)
            if e:
                out.append(e)
    return out[:MAX_SKILLS]


def machine_allowed(target):
    """Which machine skills the policy rule for this folder offers: a list of
    names, "*" (or no rule) for all, [] for none."""
    pol = core.load_policy()
    if not pol:
        return "*"
    rule = core._policy_rule(pol, os.path.realpath(target)) if target else pol.get("default")
    if rule is None:
        return "*"
    allowed = rule.get("skills", "*")
    return "*" if allowed == "*" else list(allowed or [])


def catalogue(target):
    """Project skills first (they win a name clash), then the machine's, as
    policy allows. Built host-side from the folder as it is before the run;
    a project skill written during the run is still loadable by name."""
    project = scan(os.path.join(os.path.realpath(target), PROJECT_DIR), "project") if target else []
    names = {s["name"] for s in project}
    allowed = machine_allowed(target)
    machine = [s for s in scan(MACHINE_DIR, "machine")
               if s["name"] not in names and (allowed == "*" or s["name"] in allowed)]
    return (project + machine)[:MAX_SKILLS]


def context_block(cat):
    if not cat:
        return ""
    lines = [f"- {s['name']} ({s['source']}): {s['description']}"
             + (f" — when: {s['when']}" if s.get("when") else "")
             + (f" [files: {', '.join(s['files'][:6])}]" if s.get("files") else "")
             for s in cat]
    return ("\n\n# Skills\nLoad one with the `skill` tool when its description fits the task; "
            "project skills live in .overlord/skills/ and you may improve them (the change is "
            "reviewed with everything else).\n" + "\n".join(lines))


def read_machine(name, file=None):
    """A machine skill's file, host-side, confined to the skill's folder."""
    check_name(name)
    base = os.path.realpath(os.path.join(MACHINE_DIR, name))
    if not os.path.isfile(os.path.join(base, SKILL_FILE)):
        raise SkillError(f"error: no machine skill named {name}")
    rel = safe_rel(file or SKILL_FILE)
    path = os.path.realpath(os.path.join(base, rel))
    if not path.startswith(base + os.sep) or not os.path.isfile(path):
        raise SkillError(f"error: {name} has no file {rel}")
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read(FILE_CAP + 1)
    if len(text) > FILE_CAP:
        text = text[:FILE_CAP] + f"\n… [truncated at {FILE_CAP} characters]"
    return text


def safe_rel(rel):
    rel = (rel or "").strip().replace("\\", "/")
    if not rel or rel.startswith("/") or ".." in rel.split("/") or rel.startswith("."):
        raise SkillError("error: file must be a relative path inside the skill")
    return rel


# ---------------------------------------------------------------- managing


def install(src, name=None):
    """Copy a skill folder (or a lone SKILL.md) into the machine's skills."""
    src = os.path.realpath(os.path.expanduser(src))
    if os.path.isfile(src):
        folder, single = os.path.dirname(src), src
    else:
        folder, single = src, os.path.join(src, SKILL_FILE)
    if not os.path.isfile(single):
        raise SkillError(f"error: no {SKILL_FILE} at {src}")
    with open(single, encoding="utf-8", errors="replace") as f:
        meta, _ = parse(f.read())
    name = check_name(name or meta.get("name") or os.path.basename(folder))
    dst = os.path.join(MACHINE_DIR, name)
    if os.path.exists(dst):
        raise SkillError(f"error: machine skill exists: {name} (rm it first)")
    os.makedirs(MACHINE_DIR, exist_ok=True)
    if os.path.isfile(src):
        os.makedirs(dst)
        shutil.copyfile(src, os.path.join(dst, SKILL_FILE))
    else:
        shutil.copytree(folder, dst, ignore=shutil.ignore_patterns(".*"))
    import audit
    audit.record("skills.config", op="add", skill=name, source="machine")
    return _entry(dst, "machine", name)


def create(name, description, body, target=None, when=""):
    """Scaffold a skill: in the folder (project) with target, else machine."""
    check_name(name)
    base = os.path.join(os.path.realpath(target), PROJECT_DIR) if target else MACHINE_DIR
    dst = os.path.join(base, name)
    if os.path.exists(dst):
        raise SkillError(f"error: skill exists: {dst}")
    os.makedirs(dst)
    desc = " ".join((description or "").split()) or "What this skill is for."
    text = f"---\nname: {name}\ndescription: {desc}\n"
    if when:
        text += f"when: {' '.join(when.split())}\n"
    text += "---\n\n" + (body.strip() + "\n" if (body or "").strip()
                          else f"# {name}\n\nSteps, conventions, commands.\n")
    with open(os.path.join(dst, SKILL_FILE), "w", encoding="utf-8") as f:
        f.write(text)
    if not target:
        import audit
        audit.record("skills.config", op="create", skill=name, source="machine")
    return _entry(dst, "project" if target else "machine", name)


def remove(name):
    check_name(name)
    dst = os.path.join(MACHINE_DIR, name)
    if not os.path.isfile(os.path.join(dst, SKILL_FILE)):
        raise SkillError(f"error: no machine skill named {name}")
    shutil.rmtree(dst)
    import audit
    audit.record("skills.config", op="remove", skill=name, source="machine")


def public(target=None):
    return [{k: v for k, v in s.items() if k != "path"} | {"path": s["path"]} for s in catalogue(target)]


# ---------------------------------------------------------------- cli


def cmd_skills(args):
    c = args.skills_cmd
    if c == "list":
        target = os.path.realpath(args.target or os.getcwd())
        cat = catalogue(target)
        if not cat:
            print(f"no skills: none in {os.path.join(target, PROJECT_DIR)}, none in {MACHINE_DIR}")
            return 0
        for s in cat:
            print(f"  {s['name']:24} {s['source']:8} {s['description'][:70]}"
                  + (f"  (+{len(s['files'])} file(s))" if s["files"] else ""))
        return 0
    if c == "show":
        target = os.path.realpath(args.target or os.getcwd())
        hit = next((s for s in catalogue(target) if s["name"] == args.name), None)
        if not hit:
            raise SkillError(f"error: no skill named {args.name} for {target}")
        with open(os.path.join(hit["path"], SKILL_FILE), encoding="utf-8", errors="replace") as f:
            print(f.read().rstrip())
        if hit["files"]:
            print(f"\nfiles: {', '.join(hit['files'])}")
        return 0
    if c == "add":
        e = install(args.path, args.name)
        print(f"installed machine skill {e['name']}: {e['description'][:80]}")
        return 0
    if c == "new":
        e = create(args.name, args.description or "", "", target=args.target, when=args.when or "")
        print(f"created {e['source']} skill at {e['path']}/{SKILL_FILE} — edit it")
        return 0
    if c == "rm":
        remove(args.name)
        print(f"removed machine skill {args.name}")
        return 0
    raise SkillError("error: unknown skills subcommand")


def add_skills_parser(sub):
    ps = sub.add_parser("skills", help="packaged know-how the agent loads on demand")
    ss = ps.add_subparsers(dest="skills_cmd", required=True)
    pl = ss.add_parser("list")
    pl.add_argument("-t", "--target")
    psh = ss.add_parser("show")
    psh.add_argument("name")
    psh.add_argument("-t", "--target")
    pa = ss.add_parser("add", help="install a folder (or a SKILL.md) machine-wide")
    pa.add_argument("path")
    pa.add_argument("--name")
    pn = ss.add_parser("new", help="scaffold a skill; with -t, inside that folder")
    pn.add_argument("name")
    pn.add_argument("--description")
    pn.add_argument("--when")
    pn.add_argument("-t", "--target")
    ss.add_parser("rm").add_argument("name")
    ps.set_defaults(fn=cmd_skills)
