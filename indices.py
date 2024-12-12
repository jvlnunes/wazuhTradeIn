class Event:
  def __init__(self, _index=None, _id=None, _score=None, _source=None):
    self._index  = _index
    self._id     = _id
    self._score  = _score
    self._source = _source

class Data:
    def __init__(self, action     = None, arch        = None, audit = None, aws      = None, cis      = None, command = None, 
                       docker     = None, dpkg_status = None, dstip = None, dstport  = None, dstuser  = None, 
                       extra_data = None, file        = None, gcp   = None, github   = None, hardware = None, 
                       id         = None, integration = None, level = None, ms_graph = None, netinfo  = None, 
                       office365  = None, os          = None):
      
        self.action      = action
        self.arch        = arch
        self.audit       = audit  
        self.aws         = aws      
        self.cis         = cis      
        self.command     = command
        self.docker      = docker  
        self.dpkg_status = dpkg_status
        self.dstip       = dstip
        self.dstport     = dstport
        self.dstuser     = dstuser
        self.extra_data  = extra_data
        self.file        = file
        self.gcp         = gcp        
        self.github      = github  
        self.hardware    = hardware  
        self.id          = id
        self.integration = integration
        self.level       = level
        self.ms_graph    = ms_graph  
        self.netinfo     = netinfo  
        self.office365   = office365  
        self.os          = os            

class OS:
    def __init__(self, architecture = None, build   = None, codename        = None, display_version      = None, 
                       hostname     = None, major   = None, minor           = None, name   = None, patch = None, 
                       platform     = None, release = None, release_version = None, sysname= None, 
                       version      = None):
      
        self.architecture    = architecture
        self.build           = build
        self.codename        = codename
        self.display_version = display_version
        self.hostname        = hostname
        self.major           = major
        self.minor           = minor
        self.name            = name
        self.patch           = patch
        self.platform        = platform
        self.release         = release
        self.release_version = release_version
        self.sysname         = sysname
        self.version         = version

class Agent:
    def __init__(self, id=None, ip=None, labels=None, name=None):
        self.id     = id
        self.ip     = ip
        self.labels = labels  
        self.name   = name
        
class Labels:
    def __init__(self, contrato=None, group=None, group2=None, vm=None):
        self.contrato = contrato
        self.group    = group
        self.group2   = group2
        self.vm       = vm
