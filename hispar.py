#!/usr/bin/python3
import argparse
import json
import re
from termcolor import colored as clr

### PARSER
p = argparse.ArgumentParser()
p.add_argument(
        '-l',
        '--list',
        dest="list",
        required=True,
        help="Target endpoints. Can hold both .js and regular endpoints."
        )
p.add_argument(
        '-io',
        '--inout',
        dest="inout",
        default="historical.json",
        help="input output file for results."
        )
p.add_argument(
        '-t',
        '--targets',
        dest="targets",
        required=True,
        help="Give the targets i.e. 'twitter,twimg'."
        )
p.add_argument(
        '-v',
        '--verbose',
        dest="verb",
        action="store_true",
        help="Print error messages, if they occur."
        )
args = p.parse_args()

### FUNCTIONS
def is_trash(string):
    # If string has trash i.e. ".jpg", then return True
    trash = "\.jpe?g|\.png|\.woff|\.gif|\.svg"
    if re.search(trash,string) != None:
        return True
    else:
        return False

def input_output(file):
    # Create or get an file, for updates and stuff
    try:
        with open(file,"r") as inout:
            obj = json.load(inout)
    except Exception:
        return {"jsfiles":[],"api":[],"parameters":[],"otherfiles":[],"sensitive":[],"paths":[]}
    else:
        return obj

def cprint(txt,length):
    # Print completion
    print("[",clr("COMPLETE","light_yellow"),"]",txt,clr(f"{length}","green"))

def get_info(targets,ls,obj):
    # flsdfk
    for t in targets:
        for stuff in ls:
            if t in stuff:
                if stuff not in obj:
                    obj.append(stuff)
    return obj

def get_file(file):
    # Get a file
    ls = []
    with open(file,"r") as f:
        for e in f:
            ls.append(e.rstrip())
    return ls

def get_regex(regex,text):
    # Getting the regex results
    ls = re.findall(regex,text)
    return ls

def get_params(ls,obj):
    # Getting params and placing them to object
    for par in ls:
        if "?" in par:
            par = par.replace("?","")
        elif "&" in par:
            par = par.replace("&","")
        par = par.replace("=","")

        if par not in obj:
            obj.append(par)
    return obj

def get_paths(ls,obj):
    # Get paths that have words within a wordlist
    # Whitelisted words
    words = ["adm","dash","board","cdn","cgi","about","api","counsel","help","better","log","reg","sys","bash","cache","serv","conf","cvs","git","known","abstract","acc","act","acp","add","adv","aff","age","ajax","alias","anal","annual","announ","anon","app","apache","nginx","arch","arr","art","asp","jsp","txt","xml","pyt","php","asc","asse","atta","aud","aut","avata","off","blog","book","bot","build","byp","call","care","catal","categ","cert","cfc","chan","chec","cisco","clas","client","cms","comp","conn","lib","cont","cook","corp","coup","cpan","creat","cred","cron","curr","cust","cyber","data","mana","deal","deb","decl","decr","def","dem","des","dev","dial","dif","dir","dis","dns","doc","dom","don","dot","net","down","load","draf","drop","dum","ecom","edit","elem","email","emb","emer","emp","enc","end","eng","ent","en_us","en-us","env","err","even","exam","exc","exe","exp","ext","fav","feat","feed","file","fin","fir","fla","fol","forg","form","fram","free","fron","func","gadg","gall","game","gate","gen","geo","get","git","glob","gra","gro","grid","gui","hack","hand","head","hard","heal","help","hid","his","home","host","html","http","fram","iis","image","img","inbox","inc","ind","inf","inp","inq","inl","ini","ins","ing","int","inv","item","java","jira","join","key","lab","lan","laun","lay","lead","legal","lic","link","lis","live","loc","lost","mac","mail","main","make","manu","map","mark","mast","mat","media","mem","men","merc","mess","meta","mig","misc","mob","mod","mon","mov","multi","name","nav","net","new","next","not","obj","obs","off","old","onl","open","oper","opin","opt","ord","org","orig","out","over","own","pack","page","pan","part","pass","pay","pdf","per","pho","pic","pin","plac","play","plug","pod","pol","pop","port","post","pre","pri","pro","pub","pur","que","qui","rar","rat","read","rec","red","ref","rel","rem","rend","rep","req","res","ret","rev","rout","rss","sale","safe","samp","samba","sand","save","sche","scho","scr","search","sec","sele","send","sess","set","sha","ship","shop","show","sign","simp","sing","site","sli","soft","sol","sou","spec","spo","sql","src","ssh","ssl","srv","sso","staf","stan","stag","star","stat","stor","str","stud","style","sub","succ","suff","sugg","summ","supp","suit","surv","susp","svn","swf","sync","syn","tag","talk","tap","task","team","tech","tel","tmp","temp","term","test","text","them","thank","thr","thumb","ticket","time","tiny","title","tip","today","tool","tomcat","top","tour","trac","traf","tran","trav","txt","type","unix","upd","upl","url","user","usr","util","uri","val","vbs","vehicle","vid","view","virt","visi","voip","vti","web","welc","white","who","widg","wifi","wiki","win","word","worl","work","www","zip"]
    
    # Blacklisted words (mostly names)
    removal = ["adam","wendy","yolanda","willi","virginia","traci","tracy","trinity","tricia","twaina","steven","shann","sharo","shana","shand","sandra","ruth","ronald","robin","robert","richard","rebecca","raquel","rachel","priscilla","porshea","phyllis","penny","paul","pamela","orlando","nicole","nathan","natali","monique","monica","mindy","melissa","megan","matt","lisa","lindsay","linda","leslie","lauren","laura","kristina","krista","kimberly","kathryn","james","jeff","george","elisa","deborah","david","christ","cassandra","britt","brett","ashley","april","anthony","yvonne","zach","wendi","wanda","warren","walter","vincent","victoria","vicki","veronica","vanessa","valerie","valorie","tyler","trish","travis","tracey","tonya","tonia","timothy","tiffany","thomas","theresa","adrian","adrien","aisha","alan","albert","alecia","alesha","alejandra","alexa","alfred","alice","alicia","alisha","alison","alissa","allison","alyce","alysha","alyssa","amanda","amber","andrea","andrew","angel","anita","annette","antoinette","arthur","ashlee","audra","audrey","austin","autumn","barbara","barry","becky","benjamin","bethany","betsy","betty","beverly","blair","bonnie","brandi","brandon","brandy","brenda","brian","brent","brian","bridget","brooke","caitlin","callie","camill","candace","candice","caren","karen","carla","carmen","carol","carri","cath","cecil","chad","chand","chanel","chantel","charl","chelsea","cheryl","cindy","claud","cliff","colleen","connie","constance","corinne","corey","courtney","craig","crist","cryst","cynthia","daniel","debbie","debra","denise","desiree","diana","donald","donna","edward","eileen","elaine","elise","elissa","elisha","elizabeth","ellen","emily","eric","felicia","franc","frank","fred","gabriel","garret","ginger","grace","greg","greta","gretch","gwendo","hannah","heather","heidi","helen","holly","jacquel","jamie","janet","jared","jason","jasmine","jeanette","jeanne","jenna","jennifer","jeremy","jenny","jesse","jessi","joanna","jill","jodi","john","jordan","jose","josh","julia","julie","kari","kate","katharine","katherine","kathleen","keesha","keisha","kell","kendra","kenneth","kerr","kevin","krist","larry","lasha","lasho","latish","laurie","lawrence","lindsey","loretta","lori","lynet","lynnet","margaret","maria","marie","mark-","marsha","martha","martin","mary-","melanie","meredith","michael","michel","molly","monika","morgan","nancy","natasha","nichol","patric","ramona","reggie","regina","renee","sarah","sasha","shauna","shawn","shayla","sheila","shellby","sherri","sherry","simon","steph","susan","teresa","terri","terry","town","city","farm","park","village","mount","summit","center","springs"]

    for p in ls:
        p = p.replace("/","")
        for w in words:
            if w.lower() in p.lower():
                block = False
                for b in removal:
                    if b.lower() in p.lower():
                        block = True
                if block:
                    pass
                else:
                    if p not in obj:
                        obj.append(p)
    return obj

### SCRIPT
if __name__ == "__main__":
    # Putting the list of historic content into a string
    with open(args.list, "r") as read:
        hist = read.read()

    # Making sure our targets are put into a list
    try:
        targets = args.targets.split(",")
    except Exception:
        targets = args.targets

    # Getting the object of historic content
    main_obj = input_output(args.inout)

    # Get historic JS files
    main_obj["jsfiles"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.js",hist),main_obj["jsfiles"]) # Get .js
    main_obj["jsfiles"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.mjs",hist),main_obj["jsfiles"]) # Get .mjs
    cprint("JS files found:",len(main_obj["jsfiles"]))

    # Get other extension based files
    main_obj["otherfiles"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.xml",hist),main_obj["otherfiles"]) # Get .xml
    main_obj["otherfiles"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.txt",hist),main_obj["otherfiles"]) # Get .txt
    main_obj["otherfiles"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.json",hist),main_obj["otherfiles"]) # Get .json
    main_obj["otherfiles"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.php",hist),main_obj["otherfiles"]) # Get .php
    main_obj["otherfiles"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.asp",hist),main_obj["otherfiles"]) # Get .asp
    main_obj["otherfiles"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.aspx",hist),main_obj["otherfiles"]) # Get .aspx
    main_obj["otherfiles"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.jsp",hist),main_obj["otherfiles"]) # Get .jsp
    main_obj["otherfiles"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.jspx",hist),main_obj["otherfiles"]) # Get .jspx
    cprint("Other extension files found:",len(main_obj["otherfiles"]))

    # Sensitive files
    main_obj["sensitive"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.sql",hist),main_obj["sensitive"]) # Get .sql
    main_obj["sensitive"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.config",hist),main_obj["sensitive"]) # Get .config
    main_obj["sensitive"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.cfg",hist),main_obj["sensitive"]) # Get .cfg
    main_obj["sensitive"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.env",hist),main_obj["sensitive"]) # Get .env
    main_obj["sensitive"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.ini",hist),main_obj["sensitive"]) # Get .ini
    main_obj["sensitive"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.bak",hist),main_obj["sensitive"]) # Get .bak
    main_obj["sensitive"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.old",hist),main_obj["sensitive"]) # Get .old
    main_obj["sensitive"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.backup",hist),main_obj["sensitive"]) # Get .backup
    main_obj["sensitive"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.csv",hist),main_obj["sensitive"]) # Get .csv
    main_obj["sensitive"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.log",hist),main_obj["sensitive"]) # Get .log
    main_obj["sensitive"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}\.zip",hist),main_obj["sensitive"]) # Get .zip
    cprint("Sensitive files found:",len(main_obj["sensitive"]))

    # Get parameters
    main_obj["parameters"] = get_params(get_regex("&[^\?&=,\(\);:%]+=",hist),main_obj["parameters"])
    main_obj["parameters"] = get_params(get_regex("\?[^\?&=,\(\);:%]+=",hist),main_obj["parameters"])
    cprint("Parameters found:",len(main_obj["parameters"]))

    # Get API endpoints
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/api/[a-zA-Z0-9-_/\.]*",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/v1/[a-zA-Z0-9-_/\.]*",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/v2/[a-zA-Z0-9-_/\.]*",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/v3/[a-zA-Z0-9-_/\.]*",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/v4/[a-zA-Z0-9-_/\.]*",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/v5/[a-zA-Z0-9-_/\.]*",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/1\.1/[a-zA-Z0-9-_/\.]*",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/api/[a-zA-Z0-9-_/\.]*\?[a-zA-Z0-9-_\.]*=",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/v1/[a-zA-Z0-9-_/\.]*\?[a-zA-Z0-9-_\.]*=",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/v2/[a-zA-Z0-9-_/\.]*\?[a-zA-Z0-9-_\.]*=",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/v3/[a-zA-Z0-9-_/\.]*\?[a-zA-Z0-9-_\.]*=",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/v4/[a-zA-Z0-9-_/\.]*\?[a-zA-Z0-9-_\.]*=",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/v5/[a-zA-Z0-9-_/\.]*\?[a-zA-Z0-9-_\.]*=",hist),main_obj["api"])
    main_obj["api"] = get_info(targets,get_regex("https?://[a-zA-Z0-9-_/\.]{5,}/1\.1/[a-zA-Z0-9-_/\.]*\?[a-zA-Z0-9-_\.]*=",hist),main_obj["api"])
    cprint("API endpoints found:",len(main_obj["api"]))

    # Get paths that have words contained within the wordlist
    main_obj["paths"] = get_paths(get_regex("/[a-zA-Z0-9-_]{3,20}/",hist),main_obj["paths"])
    cprint("Paths found:",len(main_obj["paths"]))

    # Overwrite old inout file
    with open(args.inout,"w") as res:
        res.write(json.dumps(main_obj, indent=4))
