from .ClassData import ClassData
import sys
class CMD():
    var = dict()
    def __init__(self):

        self.var['ycmd'] = ClassData(self)
        self.var['ClassData'] = ClassData(self)
    async def cmdrun_file(self,path):
        with open(path) as f:
            tempInside = f.readlines()
        dom =True
        doif = False
        ifrun = False
        for cmds in tempInside:
            cmd = cmds.replace('\n','').split(" ")
            if cmd[0]=="EMethod":
                dom = True
            if cmd[0]=="Eif":
                doif = False
                ifrun = False
            if dom and (doif==ifrun):
                if cmd[0]=="new":
                    self.var[cmd[1]] = ClassData(getattr(sys.modules[__name__],cmd[2]))
                elif cmd[0]=="ifreturn":
                    if cmd[2]=="==":
                        if self.getvar(cmd[1])==self.getvar(cmd[3]):
                            return
                    elif cmd[2]=="!=":
                        if self.getvar(cmd[1])!=self.getvar(cmd[3]):
                            return
                elif cmd[0]=="NMethod":
                    dom = False
                elif cmd[0]=="=":
                    self.var[cmd[1]] = ClassData(self.getvar(cmd[2]))
                elif cmd[0]=="invoke":
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                    eval("m("+args[0:-1]+")")
                elif cmd[0]=="set":
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                    self.var[cmd[4]] = ClassData(eval("m("+args[0:-1]+")"))
                elif cmds.startswith("await invoke"):
                    cmd.pop(0)
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                        await eval("m("+args[0:-1]+")")
                elif cmds.startswith("await set"):
                    cmd.pop(0)
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                    self.var[cmd[4]] = ClassData(await eval("m("+args[0:-1]+")"))
                elif cmd[0]=="import":
                    exec("import "+cmd[1])
                elif cmd[0]=="if":
                    doif = True
                    if cmd[2]=="==":
                        if self.getvar(cmd[1])==self.getvar(cmd[3]):
                            ifrun = True
                    elif cmd[2]=="!=":
                        if self.getvar(cmd[1])!=self.getvar(cmd[3]):
                            ifrun = True
    async def cmdrun(self,code):
        tempInside = code.splitlines()
        dom =True
        doif = False
        ifrun = False
        for cmds in tempInside:
            cmd = cmds.split(" ")
            if cmd[0]=="EMethod":
                dom = True
            if cmd[0]=="Eif":
                doif = False
                ifrun = False
            if dom and (doif==ifrun):
                if cmd[0]=="new":
                    self.var[cmd[1]] = ClassData(getattr(sys.modules[__name__],cmd[2]))
                elif cmd[0]=="ifreturn":
                    if cmd[2]=="==":
                        if self.getvar(cmd[1])==self.getvar(cmd[3]):
                            return
                    elif cmd[2]=="!=":
                        if self.getvar(cmd[1])!=self.getvar(cmd[3]):
                            return
                elif cmd[0]=="NMethod":
                    dom = False
                elif cmd[0]=="=":
                    self.var[cmd[1]] = ClassData(self.getvar(cmd[2]))
                elif cmd[0]=="invoke":
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                    eval("m("+args[0:-1]+")")
                elif cmd[0]=="set":
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                    self.var[cmd[4]] = ClassData(eval("m("+args[0:-1]+")"))
                elif cmds.startswith("await invoke"):
                    cmd.pop(0)
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                        await eval("m("+args[0:-1]+")")
                elif cmds.startswith("await set"):
                    cmd.pop(0)
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                    self.var[cmd[4]] = ClassData(await eval("m("+args[0:-1]+")"))
                elif cmd[0]=="import":
                    exec("import "+cmd[1])
                elif cmd[0]=="if":
                    doif = True
                    if cmd[2]=="==":
                        if self.getvar(cmd[1])==self.getvar(cmd[3]):
                            ifrun = True
                    elif cmd[2]=="!=":
                        if self.getvar(cmd[1])!=self.getvar(cmd[3]):
                            ifrun = True
    async def cmdrun_method_file(self,path,name):
        with open(path) as f:
            tempInside = f.readlines()
        dom = False
        doif = False
        ifrun = False
        for cmds in tempInside:
            cmd = cmds.replace('\n','').split(" ")
            if cmd[0]=="NMethod":
                if cmd[1]==name:
                    dom = True
            if cmd[0]=="Eif":
                doif = False
                ifrun = False
            if dom and (doif==ifrun):
                if cmd[0]=="new":
                    self.var[cmd[1]] = ClassData(getattr(sys.modules[__name__],cmd[2]))
                elif cmd[0]=="ifreturn":
                    if cmd[2]=="==":
                        if self.getvar(cmd[1])==self.getvar(cmd[3]):
                            return
                    elif cmd[2]=="!=":
                        if self.getvar(cmd[1])!=self.getvar(cmd[3]):
                            return
                elif cmd[0]=="EMethod":
                    dom = False
                elif cmd[0]=="=":
                    self.var[cmd[1]] = ClassData(self.getvar(cmd[2]))
                elif cmd[0]=="invoke":
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                    eval("m("+args[0:-1]+")")
                elif cmd[0]=="set":
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                    self.var[cmd[4]] = ClassData(eval("m("+args[0:-1]+")"))
                elif cmds.startswith("await invoke"):
                    cmd.pop(0)
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                        await eval("m("+args[0:-1]+")")
                elif cmds.startswith("await set"):
                    cmd.pop(0)
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                    self.var[cmd[4]] = ClassData(await eval("m("+args[0:-1]+")"))
                elif cmd[0]=="import":
                    exec("import "+cmd[1])
                elif cmd[0]=="if":
                    doif = True
                    if cmd[2]=="==":
                        if self.getvar(cmd[1])==self.getvar(cmd[3]):
                            ifrun = True
                    elif cmd[2]=="!=":
                        if self.getvar(cmd[1])!=self.getvar(cmd[3]):
                            ifrun = True
    async def cmdrun_method(self,code,name):
        tempInside = code.splitlines()
        dom =False
        doif = False
        ifrun = False
        for cmds in tempInside:
            cmd = cmds.split(" ")
            if cmd[0]=="NMethod":
                if cmd[1]==name:
                    dom = True
            if cmd[0]=="Eif":
                doif = False
                ifrun = False
            if dom and (doif==ifrun):
                if cmd[0]=="new":
                    self.var[cmd[1]] = ClassData(getattr(sys.modules[__name__],cmd[2]))
                    return
                elif cmd[0]=="ifreturn":
                    if cmd[2]=="==":
                        if self.getvar(cmd[1])==self.getvar(cmd[3]):
                            return
                    elif cmd[2]=="!=":
                        if self.getvar(cmd[1])!=self.getvar(cmd[3]):
                            return
                elif cmd[0]=="EMethod":
                    dom = False
                elif cmd[0]=="=":
                    self.var[cmd[1]] = ClassData(self.getvar(cmd[2]))
                elif cmd[0]=="invoke":
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                    eval("m("+args[0:-1]+")")
                elif cmd[0]=="set":
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                    self.var[cmd[4]] = ClassData(eval("m("+args[0:-1]+")"))
                elif cmds.startswith("await invoke"):
                    cmd.pop(0)
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                        await eval("m("+args[0:-1]+")")
                elif cmds.startswith("await set"):
                    cmd.pop(0)
                    if cmd[1]=="":
                        m = eval(cmd[2])
                    else:
                        c = self.var[cmd[1]]
                        m = getattr(c.Class,cmd[2])
                    arg = cmd[3].split(",")
                    args = ""
                    if cmd[3]!="":
                        for v in arg:
                            if v[0]=="\"":
                                args = args + v +","
                            else:
                                try:
                                    str(self.var[v])
                                    args = args + "self.var['" + v + "'].Class,"
                                except KeyError:
                                    args = args + v + ","
                    self.var[cmd[4]] = ClassData(await eval("m("+args[0:-1]+")"))
                elif cmd[0]=="import":
                    exec("import "+cmd[1])
                elif cmd[0]=="if":
                    doif = True
                    if cmd[2]=="==":
                        if self.getvar(cmd[1])==self.getvar(cmd[3]):
                            ifrun = True
                    elif cmd[2]=="!=":
                        if self.getvar(cmd[1])!=self.getvar(cmd[3]):
                            ifrun = True
    def getvar(self,name) -> object:
         if name[0]=="\"":
             return name[1:-1]
         else:
             try:
                 return self.var[name].Class
             except KeyError:
                 return name