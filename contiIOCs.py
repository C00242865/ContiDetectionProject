from lxml import etree
from winevt import EventLog
import json

#Free AD Tool Used by Conti for Recon
AdFindHash = ["794a5621fda2106fcb94cbd91b6ab9567fb8383caa7f62febafcf701175f2b91", "b1102ed4bca6dae6f2f498ade2f73f76af527fa803f0e0b46e100d4cf5150682", "794a5621fda2106fcb94cbd91b6ab9567fb8383caa7f62febafcf701175f2b91", "085e87a6694edafd9a614a1f1143eb85233c04afbe9f84c89ebe5aebcd14546f", "085e87a6694edafd9a614a1f1143eb85233c04afbe9f84c89ebe5aebcd14546f"]
#Uninstallers used to disable security tools
uninstallers = ['Bitdefender_2019_Uninstall_Tool.exe', 'trendmicro pass AV remove.bat', 'sophos remvDIEsophos.bat', 'sophos remvremovesophos.bat', 'sophos remvuninstallSophos.bat', 'PCHunter32.exe', 'PCHunter64.exe', 'PowerTool.exe', 'PowerTool64.exe']
#conti uninstaller tool archive hash
archive = '269bea10e27d697a849b28ed0b688b8a2b5c85d65341bde1383c14876291d7c5'
#cobalt strike hash IOCs
cobalt_hash = ['78d82b72aae1d847c64745a932bce927823337de58852833e8cafca168eb4366', '5ea267958786999986413bd982227f77716acb1f09d02ea56571631269dbdf95', '75584d0477d5340b898d2fc1eb369516b76478359e7603eba9fcb615a75247af', '3a3725bf0cca3fc3d641aed0a1280b7d957aa5c872223f1b6320f315bdea457d', '27aa9643628a7494ad3daa969c287b4119bbfdfffa943acfe2c866e1b9d965ea', '1cdfa75b103f4b3218a9f6ddec137a5438c5e6571151d0979c60d96dfbbf9231', 'e25f83836e90fe17ed5d57516219373f0c4dcf0210638501223b63091d1fc6c3', '3c4eb1e68c36e1287f0ed9c9a4470b95cf8f25b901d502fd9f5ccedec7d2ef54', '6b098b82a0ff28c9bc0f812856eb5e2a861285d9ce12f3c7374542dc3d3acfbd', 'c20d8ce3809123923b8897c97f251a766b5b56b61bd89134cb986ff10c2a309e', '47060339e9d434f361ea750916a3980bd308995c4980c91e069d0b7a664a91af', '340e3250b9d4717ca09543e34db19f5614b3bb84e93f3b6e0b467856455d2735', 'a29b4969c1f6c7759d6f94780145e126a8d67812fa388239a595472f1a9f3b13', '19bc4b2b9704a5b4aa2edef5477219cd97052833f2fc2112ec6ecf9a9027ea35', 'e9b33a2f96b60f710e14d29cb38371b587094cfc4378276eebb9701d74cd3f71', '1a0296704d9c3af491b8910ca7461d50e913c85b40c6620650ee24160849a625', '3481ec6c99e3b78793538a3a5b818384355af4eefc9624ec2d66ab96e1357aac', '92320d2f875e02f3c5f989926b1af60f20caea0034a4728d2f898ba8bafada3f', '3f164991219c1804afa1fb75ee79d5cbfc0100ea71a90840cbad7352838a637b', '627719d254c8168c56c8fbd40c88fbb65ebe141995b8c65763103aa07e117d47', '13feaa32e4b03ede8799e5bee6f8d54c3af715a6488ad32f6287d8f504c7078b', 'c50183eed715ec2392249e334940acf66315797a740a8fe782934352fed144c6', '6a659500d1a672ad2d57cc0b004ea40b1479ab4b968858ba873e4def851d62bd', '760664d7f0770ab440c8f24cd48c132372fbebfe6338c59801000613a0f4b4fe', 'd440e4494adcfd94004e9ead2adcaaaf22696c71fc51246b881d628567ce1111']
#Known Conti C2 IP Addresses from leaks and advisories
c2Ips = ['82.118.21.1', '85.93.88.165', '162.244.80.235', '185.141.63.120', '23.82.140.137', '23.106.160.174']
#kerberoasting known hash IOCs
kerbehashes = ['abbe373077c72125901669d1b9f74b9eecd95eeda2c3b794197a20ea49cd25c0', '495da9bb972019fae2c8a4d38846e15b9c364ef7189377f2c93b86791a1b210d', '4729c83292e034642fd1081ddd4d0329bc9f57b9be989b647a025ffacdd55036']
#Proxifier Proxy IOCs
proxifierhashes = ['68e1b13bbe2a1de32c41a2db53999b9207ee7dbdc042e19cabd83cab5ef785a6', '167ecba4e15f0310770f265b0fbb00aaf3c4f04ee17e1c0cc26304152e8a1f4f', '271fcf35f2da45bd6ea567f86cd1ec5179905f2bdd70c392aad76433890a525b', '5527dc7eac16fbc16e55829245f0d0fcb3f8d44b962d314fb5a934a804802143', '1664da61de30fa7103ee5ef09c9f59a117aa0437ee35f800e722097f38ca27c9', '8dc3afb39efabc780f2272b33cb0f8b42504991edbfe5f32ecce6abe10d0afe7']
#rclone data exfilltration IOCs
rclonehashes = ['861bc2cf05107d91b03406231e1e04839c7ed7e0e325f95d68b28f61a202fbc8', 'd47e2b72f71a35a201156f6611a934b391d52629a378587fb67bbb351dd50269', '9b5d1f6a94ce122671a5956b2016e879428c74964174739b68397b6384f6ee8b', '1f7b6fc3326be16f1847517d53bbf44f024b3cc8bccf69c59e107073db82ae02', '1da5ea82ddc736eefb5e014ab55ba1ee340c71474af11067666de9cfb8c1579b', 'ba110536613c50460ff5be6413d2f58bbe80ba3fee809ff6a27a2c7d13a47e91']
#router scan recon tool IOCs
routerscan = ['b875051a6d584b37810ea48923af45e20d1367adfa94266bfe47a1a35d76b03a', '1729fa47ede6a8b5046fef6c538431d4e8bb9020d9124e20c872e01495f91fb6', '86db3629d98f47ea078ee41b54f2833bfbd5f632d0fce3b342e099aad368421d', '91ae5e6459a40c8084be102693a8c09d5179a3e78b8a11860cce6e69ca533623', '307b3453bff0e5c2a7f5a677b6c1a64a455850d6d18952d5061a3649fbe09666', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '740e97254ae4104a588557e9d5abbe3a75896efe87e291201f49eb64c81dfc45', '7dd77348867a776967eb573c31c4b32211d3950bb3392187c30860f52538cab2', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '60c06e0fa4449314da3a0a87c1a9d9577df99226f943637e06f61188e5862efa', '740e97254ae4104a588557e9d5abbe3a75896efe87e291201f49eb64c81dfc45', '7dd77348867a776967eb573c31c4b32211d3950bb3392187c30860f52538cab2', '62440c93be34b792656b3c66ada73a17aea6d8260590f1cd75bf338e7893414b', '60c06e0fa4449314da3a0a87c1a9d9577df99226f943637e06f61188e5862efa', '740e97254ae4104a588557e9d5abbe3a75896efe87e291201f49eb64c81dfc45', 'a521b9bfd7b469d84a7910efdc8b385f087d85f3874ebe37c0c7059e0a23b7ba', '62440c93be34b792656b3c66ada73a17aea6d8260590f1cd75bf338e7893414b', '60c06e0fa4449314da3a0a87c1a9d9577df99226f943637e06f61188e5862efa', '18229920a45130f00539405fecab500d8010ef93856e1c5bcabf5aa5532b3311', 'a521b9bfd7b469d84a7910efdc8b385f087d85f3874ebe37c0c7059e0a23b7ba', '62440c93be34b792656b3c66ada73a17aea6d8260590f1cd75bf338e7893414b', '2988be6f3413a90106932f3fc8d32d62b459289846150b75cf5e0831c980cf6b', '9c2aaf899342146ef6912e337bf893bc2f6835e66a8bcce431df5c134c4ba887', '7d06d988198e18dadf31816ba834dba9c0c333009bd14b8cdea3fcb2fcabc519', '3b59889ee4189c7e2077e35c3f9884d09cd6bc50b7007622bb3e6a4def882c5e', 'b91166d5623d4077003ae8527e9169092994f5c189c8a3820b32e204b4230578', '2893b648d0e972e6c5dede0919ab35ad13e9a244c0685822601f93310e73724e', '3653d87909a0315231d2adcbf3316be0d088cfd72abab00911a3afa42444e1ad', '0b1401a84b1fe4b7e6676c5c300643c025dfdf89e57b0bde2c67fca2d0ef4ab7', '9940cec1ad427946a67ec5b3b15f022cc64acea99da179457a117d706ec14207']
#softperfect network scanner
softperfect = ['libsmb2.dll', 'libsmi2.dll', 'netscan.exe', 'result.xml', 'netscan.xml']
#AnyDesk Hash
anydesk = '4de898c139fb5251479ca6f9ec044cac4d83a2f5d1113b7a4b8f13468a130c97'
#Hashes of known Conti Binaries
contibinary = ['707b752f6bd89d4f97d08602d0546a56d27acfe00e6d5df2a2cb67c5e2eeee30', '52cdd111a81bb7b55b1bab28d19014fda0cfc323c11dcb6e9f8e60112eac8b1d']
#bazaarloader IOCs
bazaarloader = ['c340cdccf8bccec7270e1fe2ca48cb329b8270872fbf1a84c7f55642962dc1acd', 'd28bb0ac47e72ddbaa7a935ea63d29b8', '25d3dfbe0636b3fdfa081f83bd116e81', '98908ad2dcc47b791cad2bb71af825a8', '71a33bfb2ff48a8ca32d396f5a61d143']
#malicious command line observed used by Conti to download and install AnyDesk
anydeskmalcmd = ['AnyDesk.exe --install', 'AnyDesk --start-with-win --silent', 'echo J9kzQ2Y0qO | ', 'net user oldadministrator "qc69t4B#Z0kE3" /add', 'net localgroup Administrators oldadministrator /ADD', 'reg add "HKEY_LOCAL_MACHINESoftwareMicrosoftWindows NTCurrentVersionWinlogonSpecialAccountsUserlist" /v oldadministrator /t REG_DWORD /d 0 /f']
#url paths observed from Conti Leaks and Advisories. May indicate C2, malware distrubtion, compromise...
urlpaths = ['/Menus.aspx', '/menus.aspx', '/us/ky/louisville/312-s-fourth-st.html', 'tapavi.com', 'docns.com', 'm232fdxbfmbrcehbrj5iayknxnggf6niqfj6x4iedrgtab4qupzjlaid.onion', 'contirecovery.best', "badiwaw.com", "balacif.com", "barovur.com", "basisem.com", "bimafu.com", "bujoke.com", "buloxo.com", "bumoyez.com", "bupula.com", "cajeti.com", "cilomum.com", "codasal.com", "comecal.com", "dawasab.com", "derotin.com", "dihata.com", "dirupun.com", "dohigu.com", "dubacaj.com", "fecotis.com", "fipoleb.com", "fofudir.com", "fulujam.com", "ganobaz.com", "gerepa.com", "gucunug.com", "guvafe.com", "hakakor.com", "hejalij.com", "hepide.com", "hesovaw.com", "hewecas.com", "hidusi.com", "hireja.com", "hoguyum.com", "jecubat.com", "jegufe.com", "joxinu.com", "kelowuh.com", "kidukes.com", "kipitep.com", "kirute.com", "kogasiv.com", "kozoheh.com", "kuxizi.com", "kuyeguh.com", "lipozi.com", "lujecuk.com", "masaxoc.com", "mebonux.com", "mihojip.com", "modasum.com", "moduwoj.com", "movufa.com", "nagahox.com", "nawusem.com", "nerapo.com", "newiro.com", "paxobuy.com", "pazovet.com", "pihafi.com", "pilagop.com", "pipipub.com", "pofifa.com", "radezig.com", "raferif.com", "ragojel.com", "rexagi.com", "rimurik.com", "rinutov.com", "rusoti.com", "sazoya.com", "sidevot.com", "solobiv.com", "sufebul.com", "suhuhow.com", "sujaxa.com", "tafobi.com", "tepiwo.com", "tifiru.com", "tiyuzub.com","tubaho.com", "vafici.com", "vegubu.com", "vigave.com", "vipeced.com", "vizosi.com", "vojefe.com", "vonavu.com", "wezeriw.com", "wideri.com", "wudepen.com", "wuluxo.com", "wuvehus.com", "wuvici.com", "wuvidi.com", "xegogiv.com", "xekezix.com"]
#partial Registry Run Key Paths
runkeys = ['CurrentVersion\Run', 'Policies\Explorer\Run', 'Group Policy\Scripts', 'Windows\System\Scripts', 'CurrentVersion\Windows\Load', 'CurrentVersion\Windows\Run', 'CurrentVersion\Winlogon\Shell', 'Notify', 'Userinit', 'CurrentVersion\Drivers32', 'Session Manager\BootExecute', 'CurrentVersion\AeDebug', 'UserInitMprLogonScript', 'user shell folders\startup']
#Strings associated with RCE Tool Pipes
pipeRCETools = ['paexec', 'remcom', 'csexec']
#Strings associated with Credential Dumping Tool Pipes
pipeCredDump = ['lsadump', 'cachedump', 'wceservicepipe']
#Strings associated with Cobalt Strike Pipes
cobaltStrikePipe = ['MSSE', 'postex', 'status', 'msagent']
query = EventLog.Query("Microsoft-Windows-Sysmon/Operational")

iocfound = False
genericioc = False
open("ContiLog", "w").close()

for event in query:
    if event.System.EventID == '3':
        for item in event.EventData.Data:
            if item['Name'] == 'DestinationIp' and str(item.cdata) in c2Ips:
                print('Possible Conti C2 Traffic Detected')
                iocfound = True
                f = open('ContiLog', 'a')
                f.write("\n" + 'Possible Conti C2 Traffic Detected' + "\n\n")
                root = etree.fromstring(event.xml)
                f.write(etree.tostring(root, pretty_print=True).decode())
                f.close()
    if event.System.EventID == '12' or event.System.EventID == '13' or event.System.EventID == '14':
        for item in event.EventData.Data:
            if item['Name'] == 'TargetObject':
                for key in runkeys:
                    if key in str(item.cdata):
                        print('Registry Run Key Added or Modified')
                        genericioc = True
                        f = open('ContiLog', 'a')
                        f.write("\n" + 'Registry Run Key Added or Modified' + "\n\n")
                        root = etree.fromstring(event.xml)
                        f.write(etree.tostring(root, pretty_print=True).decode())
                        f.close()
    if event.System.EventID == '17' or event.System.EventID == '18':
        for item in event.EventData.Data:
            if item['Name'] == 'PipeEvent':
                for pipe in pipeRCETools:
                    if pipe in str(item.cdata):
                        print('Possible Pipe created or connected for RCE')
                        genericioc = True
                        f = open('ContiLog', 'a')
                        f.write("\n" + 'Possible Pipe created or connected for RCE' + "\n\n")
                        root = etree.fromstring(event.xml)
                        f.write(etree.tostring(root, pretty_print=True).decode())
                        f.close()
                for pipe in pipeCredDump:
                    if pipe in str(item.cdata):
                        print('Possible Pipe created or connected used for Credential Dumping')
                        genericioc = True
                        f = open('ContiLog', 'a')
                        f.write("\n" + 'Possible Pipe created or connected used for Credential Dumping' + "\n\n")
                        root = etree.fromstring(event.xml)
                        f.write(etree.tostring(root, pretty_print=True).decode())
                        f.close()
                for pipe in cobaltStrikePipe:
                    if pipe in str(item.cdata):
                        print('Possible Pipe created or connected used for Cobalt Strike')
                        genericioc = True
                        f = open('ContiLog', 'a')
                        f.write("\n" + 'Possible Pipe created or connected used for Cobalt Strike' + "\n\n")
                        root = etree.fromstring(event.xml)
                        f.write(etree.tostring(root, pretty_print=True).decode())
                        f.close()
    if event.System.EventID == '17':
        for item in event.EventData.Data:
            if item['Name'] == 'ImageLoaded':
                if 'iphlpapi.dll' in item.cdata:
                    print('DLL used to call GetIpNetTable() loaded')
                    iocfound = True
                    f = open('ContiLog', 'a')
                    f.write("\n" + 'DLL used to call GetIpNetTable() loaded' + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                elif 'Netapi32.dll' in item.cdata:
                    print('DLL used to call  NetShareEnum() loaded')
                    iocfound = True
                    f = open('ContiLog', 'a')
                    f.write("\n" + 'DLL used to call NetShareEnum() loaded' + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
    if event.System.EventID == '19' or event.System.EventID == '20' or event.System.EventID == '21':
        print('WMI Activity Detected')
        genericioc = True
        f = open('ContiLog', 'a')
        f.write("\n" + 'WMI Activity Detected' + "\n\n")
        root = etree.fromstring(event.xml)
        f.write(etree.tostring(root, pretty_print=True).decode())
        f.close()
    if event.System.EventID == '22':
        for item in event.EventData.Data:
            if item['Name'] == 'QueryName':
                for url in urlpaths:
                    if str(item.cdata).find(url) > -1:
                        print('Possible Conti DNS Request Detected')
                        iocfound = True
                        f = open('ContiLog', 'a')
                        f.write("\n" + 'Possible Conti DNS Request Detected' + "\n\n")
                        root = etree.fromstring(event.xml)
                        f.write(etree.tostring(root, pretty_print=True).decode())
                        f.close()
    if event.System.EventID == '1':
        for item in event.EventData.Data:
            if item['Name'] == 'CommandLine':
                for cmdsnippet in anydeskmalcmd: 
                    if cmdsnippet in str(item.cdata):
                        print('Command Line used by Conti to install AnyDesk detected')
                        iocfound = True
                        f = open('ContiLog', 'a')
                        f.write("\n" + 'Command Line used by Conti to install AnyDesk detected' + "\n\n")
                        root = etree.fromstring(event.xml)
                        f.write(etree.tostring(root, pretty_print=True).decode())
                        f.close()
                if str(item.cdata).find('vssadmin') != -1 and str(item.cdata).find('delete') != -1 and str(item.cdata).find('shadows') != -1:
                    print('Shadow Copy Deletion Detected')
                    genericioc = True
                    f = open('ContiLog', 'a')
                    f.write("\n" + 'Shadow Copy Deletion Detected' + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                if str(item.cdata).find('wmic') != -1 and str(item.cdata).find('shadowcopy') != -1 and str(item.cdata).find('delete') != -1:
                    print('Shadow Copy Deletion through WMI Detected')
                    genericioc = True
                    f = open('ContiLog', 'a')
                    f.write("\n" + 'Shadow Copy Deletion through WMI Detected' + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                if str(item.cdata).find('vssadmin') != -1 and str(item.cdata).find('resize') != -1 and str(item.cdata).find('shadowstorage') != -1:
                    print('Shadow Storage Resize Detected')
                    genericioc = True
                    f = open('ContiLog', 'a')
                    f.write("\n" + 'Shadow Storage Resize Detected' + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                if str(item.cdata).find('net') != -1 and str(item.cdata).find('stop') != -1:
                    print('Possible Disabling of Services')
                    genericioc = True
                    f = open('ContiLog', 'a')
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                if str(item.cdata).find('wevtutil') != -1 and str(item.cdata).find('cl') != -1 and str(item.cdata).find('security') != -1:
                    print('Possible Command to Clear Windows security events')
                    genericioc = True
                    f = open('ContiLog', 'a')
                    f.write("\n" + 'Possible Command to Clear Windows security events' + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                if str(item.cdata).find('psexec') != -1:
                    print('Possible PsExec use for SMB Discovery detected')
                    genericioc = True
                    f = open('ContiLog', 'a')
                    f.write("\n" + 'Possible PsExec use for SMB Discovery detected' + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()     
    for item in event.EventData.Data:
        if str(item['Name']).lower() == 'hashes':
            shaindex = str(item.cdata).find("SHA256=")
            if shaindex >= 0:
                shaindex = str(item.cdata).find("SHA256=") + 7
                sha256 = str(item.cdata)[shaindex:shaindex+64].lower()
                if sha256 in AdFindHash:
                    print("AD Tool used by Conti Found")
                    f = open('ContiLog', 'a')
                    f.write("\n" + "AD Tool used by Conti Found" + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                    iocfound = True
                elif sha256 == archive:
                    print("Conti Archive File Found")
                    f = open('ContiLog', 'a')
                    f.write("\n" + "Conti Archive File Found" + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                    iocfound = True
                elif sha256 in cobalt_hash:
                    print("Cobalt Strike IOC Found")
                    f = open('ContiLog', 'a')
                    f.write("\n" + "Cobalt Strike IOC Found" + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                    iocfound = True
                elif sha256 in kerbehashes:
                    print("Tool used by Conti for Kerberoasting Found")
                    f = open('ContiLog', 'a')
                    f.write("\n" + "Tool used by Conti for Kerberoasting Found" + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                    iocfound = True
                elif sha256 in routerscan:
                    print("Recon Tool used by Conti Found")
                    f = open('ContiLog', 'a')
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                    iocfound = True
                elif sha256 in proxifierhashes:
                    print("Proxy used by Conti Found")
                    f = open('ContiLog', 'a')
                    f.write("\n" + "Proxy Tool used by Conti Found" + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                    iocfound = True
                elif sha256 in rclonehashes:
                    print("Exfiltration tool used by Conti Found")
                    f = open('ContiLog', 'a')
                    f.write("\n" + "Exfiltration tool used by Conti Found" + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                    iocfound = True
                elif sha256 in proxifierhashes:
                    print("Proxy Tool used by Conti Found")
                    f = open('ContiLog', 'a')
                    f.write("\n" + "Proxy Tool used by Conti Found" + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                    iocfound = True
                elif sha256 == anydesk:
                    print("AnyDesk Executable Found")
                    f = open('ContiLog', 'a')
                    f.write("\n" + "AnyDesk Executable Found" + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                    iocfound = True
                elif sha256 == bazaarloader:
                    print("BazaarLoader IOC Found")
                    f = open('ContiLog', 'a')
                    f.write("\n" + "BazaarLoader IOC Found" + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                    iocfound = True
                elif sha256 == contibinary:
                    print("Conti Binary/Payload Found")
                    f = open('ContiLog', 'a')
                    f.write("\n" + "Conti Binary/Payload Found" + "\n\n")
                    root = etree.fromstring(event.xml)
                    f.write(etree.tostring(root, pretty_print=True).decode())
                    f.close()
                    iocfound = True
        elif item.cdata in uninstallers:
            print("Tool used by Conti to disable defences Found: " + item.cdata)
            f = open('ContiLog', 'a')
            f.write("\n" + "Tool used by Conti to disable defences Found: " + item.cdata + "\n\n")
            root = etree.fromstring(event.xml)
            f.write(etree.tostring(root, pretty_print=True).decode())
            f.close()
            iocfound = True
        elif item.cdata in softperfect:
            print("Tool used by Conti to network scan Found: " + item.cdata)
            f = open('ContiLog', 'a')
            f.write("\n" + "Tool used by Conti to network scan Found: " + item.cdata + "\n\n")
            root = etree.fromstring(event.xml)
            f.write(etree.tostring(root, pretty_print=True).decode())
            f.close()
            iocfound = True

security = EventLog.Query('Security')
bruteForceDict = dict()
smbbruteForceDict = dict()
for event in security:
    if event.System.EventID == '4624' or event.System.EventID == '4625':
        for item in event.EventData.Data:
            if item['Name'] == 'LogonType' and item.cdata == '10':
                print('Remote Desktop Activity Detected')
                genericioc = True
                f = open('ContiLog', 'a')
                f.write("\n" + "Remote Desktop Activity Detected" + "\n\n")
                root = etree.fromstring(event.xml)
                f.write(etree.tostring(root, pretty_print=True).decode())
                f.close()
        if event.System.EventID == '4625':           
            for data in event.EventData.Data:
                if data['Name'] == 'TargetUserName' and data.cdata != 'SYSTEM':
                    if data.cdata not in bruteForceDict:
                        
                        if len(bruteForceDict) == 0:
                            bruteForceDict['Total'] = dict()
                        bruteForceDict[data.cdata] = dict()
                        eventdate = event.System.TimeCreated['SystemTime'].split('T', 1)[0]
                        bruteForceDict[data.cdata][eventdate] = int(1)
                        if  eventdate not in bruteForceDict['Total']:
                            bruteForceDict['Total'][eventdate] = int(1)
                        else:
                            bruteForceDict['Total'][eventdate] = bruteForceDict['Total'][eventdate] + 1
                    else:
                        eventdate = event.System.TimeCreated['SystemTime'].split('T', 1)[0]
                        if eventdate not in bruteForceDict[data.cdata]:
                            bruteForceDict[data.cdata][eventdate] = int(1)
                        else:
                            bruteForceDict[data.cdata][eventdate] = bruteForceDict[data.cdata][eventdate] + 1
                        if  eventdate not in bruteForceDict['Total']:
                            bruteForceDict['Total'][eventdate] = int(1)
                        else:
                            bruteForceDict['Total'][eventdate] = bruteForceDict['Total'][eventdate] + int(1)
    if event.System.EventID == '4720':
        print('Local Account Creation Found')
        genericioc = True
        f = open('ContiLog', 'a')
        f.write("\n" + "Local Account Creation Found" + "\n\n")
        root = etree.fromstring(event.xml)
        f.write(etree.tostring(root, pretty_print=True).decode())
        f.close()
    if event.System.EventID == '4698':
        print('Scheduled Task Creation Found')
        genericioc = True
        f = open('ContiLog', 'a')
        f.write("\n" + "Scheduled Task" + "\n\n")
        root = etree.fromstring(event.xml)
        f.write(etree.tostring(root, pretty_print=True).decode())
        f.close()
    if event.System.EventID == '5168':
        print('Failed SMB Activity')
        genericioc = True
        f = open('ContiLog', 'a')
        f.write("\n" + "Failed SMB Activity" + "\n\n")
        root = etree.fromstring(event.xml)
        f.write(etree.tostring(root, pretty_print=True).decode())
        f.close()
        for data in event.EventData.Data:
                if data['Name'] == 'SubjectUserName':
                    if data.cdata not in smbbruteForceDict:
                        
                        if len(smbbruteForceDict) == 0:
                            smbbruteForceDict['Total'] = dict()
                        smbbruteForceDict[data.cdata] = dict()
                        smbeventdate = event.System.TimeCreated['SystemTime'].split('T', 1)[0]
                        smbbruteForceDict[data.cdata][eventdate] = int(1)
                        if  eventdate not in smbbruteForceDict['Total']:
                            smbbruteForceDict['Total'][eventdate] = int(1)
                        else:
                            smbbruteForceDict['Total'][eventdate] = smbbruteForceDict['Total'][eventdate] + 1
                    else:
                        eventdate = event.System.TimeCreated['SystemTime'].split('T', 1)[0]
                        if eventdate not in smbbruteForceDict[data.cdata]:
                            smbbruteForceDict[data.cdata][eventdate] = int(1)
                        else:
                            smbbruteForceDict[data.cdata][eventdate] = smbbruteForceDict[data.cdata][eventdate] + 1
                        if  eventdate not in smbbruteForceDict['Total']:
                            smbbruteForceDict['Total'][eventdate] = int(1)
                        else:
                            smbbruteForceDict['Total'][eventdate] = smbbruteForceDict['Total'][eventdate] + int(1)
f = open('ContiLog', 'a')
f.write("\n" + "Failed Login Activity Summary" + "\n\n")
#output = pprint.pformat(bruteForceDict)
f.write(json.dumps(bruteForceDict, indent=4))
f.write("\n" + "Failed SMB Activity Summary" + "\n\n")
f.write(json.dumps(smbbruteForceDict, indent=4))
f.close()
if iocfound:
    print("Conti IOC Found: Output results to contilog.txt....")
elif genericioc:
    print('Generic IOCs found: Output results to contilog.txt.... ')
else:
    print("No Indicators of Conti Intrusion found")
        