unit Sniffer;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils,
  INIFiles, Sockets, DateUtils,
  Pcap;

const
  BUFLEN = 65535;

  DATALINK_ETHERNET = 1;

  ETHERTYPE_IPV4      = $0800;
  ETHERTYPE_IPV6      = $86DD;
  ETHERTYPE_ARP       = $0806;
  ETHERTYPE_RARP      = $8035;
  ETHERTYPE_APPLETALK = $809B;
  ETHERTYPE_SNMP      = $814C;
  ETHERTYPE_LLDP      = $88CC;

type
  TErrBuff = array[0..PCAP_ERRBUF_SIZE] of Char;

  TSnifferException = class(Exception);

  TSnifferHandler = procedure(ASecondsSinceStart : double; ALength : integer) of object;

  TSnifferLogger = procedure(AMessage : String; ASecondsSinceStart : double) of object;

  TSnifferThreadLogger = procedure(AMessage : String) of object;

  THardwareAddress = packed record
    Bytes : array[1..6] of byte;
  end;

  PEthernetHeader = ^TEthernetHeader;
  TEthernetHeader = packed record
    DestinationHost : THardwareAddress;
    SourceHost : THardwareAddress;
    EthernetType : Word;
  end;

  PIPv4Header = ^TIPv4Header;
  TIPv4Header = packed record
    VersionIHL : byte;
    TOS : byte;
    TotalLength : SmallInt;
    Identification : SmallInt;
    FlagsFO : SmallInt;
    TTL : byte;
    Protocol : byte;
    CRC : SmallInt;
    SourceIP : TInAddr;
    DestinationIP : TInAddr;
    OptionPadding : Cardinal;
  end;

  PARPHeader = ^TARPHeader;
  TARPHeader = packed record
    HardwareType : Word;
    ProtocolType : Word;
    HardwareAddresLength : byte;
    ProtocolAddressLength : byte;
    OperationCode : Word;
    SenderHardwareAddress : THardwareAddress;
    SenderIPAddress : TInAddr;
    TargetHardwareAddress : THardwareAddress;
    TargetIPAddress : TInAddr;
  end;

  TPacketHandler = class(TObject)
  private
    FLogger : TSnifferThreadLogger;
  public
    constructor Create(ALogger : TSnifferThreadLogger);
    procedure HandleARP(APkt : PPChar);
  end;

  TSnifferThread = class(TThread)
  private
    FPcapHandle : PPcap;
    FSnifferHandler : TSnifferHandler;
    FSnifferThreadLogger : TSnifferThreadLogger;
    FPacketHandler : TPacketHandler;
  public
    constructor Create(APcapHandle : PPcap; ASnifferHandler : TSnifferHandler; ASnifferThreadLogger : TSnifferThreadLogger);
    procedure Execute; override;
    procedure DoLog(AMessage : String);
  end;

  TSniffer = class(TComponent)
  private
    FDevice: PChar;
    FPcapLibVersion : PChar;
    FPcapErrBuff : TErrBuff;
    FLinkType : integer;
    FNet : PDWord;
    FMask : PDword;
    FPcapHandle : PPcap;
    FSnifferHandler : TSnifferHandler;
    FSnifferLogger : TSnifferLogger;
    FSnifferThread : TSnifferThread;
    FStarted : boolean;
    FTimeStarted : TDateTime;

    procedure DoLog(AMessage : String);
    procedure CheckForError(AMethod : String);
    function CharArrayToString(ACharArray : array of Char) : String;
    function IntegerToDottedDecimal(AWord : DWord) : String;
    function GetInterfaceNet : string;
    function GetInterfaceMask : string;
    function GetSecondsSinceStart : double;
  public
    constructor Create(AOwner : TComponent); override;
    procedure LoadFromConfig(APath : String);
    procedure Setup;
    procedure Start;
    procedure Stop;

    property PcapLibVersion : PChar read FPcapLibVersion;
    property PcapDevice : PChar read FDevice;
    property LinkType : integer read FLinkType;
    property Handler : TSnifferHandler read FSnifferHandler write FSnifferHandler;
    property Logger : TSnifferLogger read FSnifferLogger write FSnifferLogger;
    property InterfaceNet : String read GetInterfaceNet;
    property InterfaceMask : String read GetInterfaceNet;
    property SecondsSinceStart : double read GetSecondsSinceStart;
  end;

var
  TheSniffer : TSniffer;

implementation

function HardwareAddressToStr(Bytes : array of byte) : string;
var
  I : integer;
  S : String;
begin
  S := '';
  for I := Low(Bytes) to High(Bytes) do
    S := S + Format('%.2x:', [Bytes[I]]);

  HardwareAddressToStr := LeftStr(S, 17);
end;

constructor TPacketHandler.Create(ALogger : TSnifferThreadLogger);
begin
  FLogger := ALogger;
end;

procedure TPacketHandler.HandleARP(APkt : PPChar);
var
  ARPHeader : PARPHeader;
begin
  ARPHeader := @PChar(APkt + SizeOf(TEthernetHeader))^;

  FLogger(Format('ARP - Sender: %s (%s), Target: %s (%s)',
    [NetAddrToStr(ARPHeader^.SenderIPAddress), HardwareAddressToStr(ARPHeader^.SenderHardwareAddress.Bytes),
     NetAddrToStr(ARPHeader^.TargetIPAddress), HardwareAddressToStr(ARPHeader^.TargetHardwareAddress.Bytes)]));
end;

constructor TSnifferThread.Create(APcapHandle : PPcap; ASnifferHandler : TSnifferHandler; ASnifferThreadLogger : TSnifferThreadLogger);
begin
  FPcapHandle := APcapHandle;
  FSnifferHandler := ASnifferHandler;
  FSnifferThreadLogger := ASnifferThreadLogger;
  FreeOnTerminate := true;

  FPacketHandler := TPacketHandler.Create(FSnifferThreadLogger);

  inherited Create(true);
end;

procedure TSnifferThread.Execute;
var
  Res : integer;
  PktHeader : PPcap_Pkthdr;
  Pkt : PPChar;
  Len : Integer;
  EthernetHeader : PEthernetHeader;
begin
  DoLog('Starting sniffer thread');

  while true do
  begin
    Res := pcap_next_ex(FPcapHandle, @PktHeader, @Pkt);
    if Res = 0 then
    begin
      continue;
    end
    else if Res < 0 then
    begin
      DoLog('Res < 0, breaking');
      break;
    end;

    Len := PktHeader^.caplen;
    TheSniffer.Handler(TheSniffer.SecondsSinceStart, Len);

    if TheSniffer.LinkType = DATALINK_ETHERNET then
    begin
      EthernetHeader := @Pkt^;
      DoLog('Ethernet: ' + HardwareAddressToStr(EthernetHeader^.SourceHost.Bytes) + ' -> ' + HardwareAddressToStr(EthernetHeader^.DestinationHost.Bytes));

      case Swap(EthernetHeader^.EthernetType) of
        ETHERTYPE_IPV4 : DoLog('IPv4');
        ETHERTYPE_IPV6 : DoLog('IPv6');
        ETHERTYPE_ARP  :
          begin
            FPacketHandler.HandleARP(@Pkt);
          end;
      else
        DoLog('Other: ' + Format('%.2x', [EthernetHeader^.EthernetType]));
      end;
    end;

  end;

  DoLog('Finished sniffing');
end;

procedure TSnifferThread.DoLog(AMessage : String);
begin
  if Assigned(FSnifferThreadLogger) then
    FSnifferThreadLogger(Format('%s', [AMessage]));
end;

constructor TSniffer.Create(AOwner : TComponent);
begin
  FDevice := '';
  FStarted := false;

  inherited Create(AOwner);
end;

procedure TSniffer.DoLog(AMessage : String);
begin
  if Assigned(FSnifferLogger) then
    FSnifferLogger(Format('%s', [AMessage]), GetSecondsSinceStart());
end;

procedure TSniffer.LoadFromConfig(APath : String);
var
  INIFile : TINIFile;
begin
  if APath = '' then
    exit;

  try
    INIFile := TIniFile.Create(APath);
    FDevice := PChar(INIFile.ReadString('config', 'device', ''));
  finally
    INIFile.Free;
  end;
end;

procedure TSniffer.Setup;
var
  AllDevs : PPPcap_If;
  Dev : PPcap_If;
  DevAddr : PPcap_Addr;
begin
  FPcapLibVersion := pcap_lib_version();

  DoLog(StrPas(TheSniffer.PcapLibVersion));

  DoLog(Format('Ethernet header length is %d bytes', [SizeOf(TEthernetHeader)]));
  DoLog(Format('IPv4 header length is %d bytes', [SizeOf(TIPv4Header)]));
  DoLog(Format('ARP header length is %d bytes', [SizeOf(TARPHeader)]));

  if FDevice = '' then
  begin
    FDevice := pcap_lookupdev(FPcapErrBuff);
    if not Assigned(FDevice) then
      CheckForError('pcap_lookupdev');
  end;

  if pcap_lookupnet(FDevice, @FNet, @FMask, FPcapErrBuff) = -1 then
    CheckForError('pcap_lookupnet');

  if pcap_findalldevs(@AllDevs, FPcapErrBuff) = -1 then
    CheckForError('pcap_findalldevs');

  Dev := AllDevs^;
  while Dev <> nil do
  begin
    DoLog('Found device: ' + StrPas(Dev^.name));
    DevAddr := Dev^.addresses;
    while DevAddr <> nil do
    begin
      if DevAddr^.addr^.sa_family = AF_INET then
      begin
        DoLog('IP address: ' + NetAddrToStr(DevAddr^.addr^.sin_addr));
        DoLog('Netmask: ' + NetAddrToStr(DevAddr^.netmask^.sin_addr));
        // DoLog('  Broadcast address: ' + NetAddrToStr(DevAddr^.broadaddr^.sin_addr));
      end;
      DevAddr := DevAddr^.next;
    end;
    Dev := Dev^.next;
  end;

  pcap_freealldevs(AllDevs^);
end;

procedure TSniffer.Start;
begin
  if Assigned(FSnifferThread) then
    raise TSnifferException.Create('SnifferThread already running');

  FPcapHandle := pcap_open_live(FDevice, BUFLEN, 1, 1000, FPcapErrBuff);
  if not Assigned(FPcapHandle) then
  begin
    CheckForError('pcap_open_live');
  end;

  FLinkType := pcap_datalink(FPcapHandle);
  DoLog('Device is of linktype ' + StrPas(pcap_datalink_val_to_description(LinkType)));

  FTimeStarted := Now();

  FSnifferThread := TSnifferThread.Create(FPcapHandle, FSnifferHandler, @DoLog);
  FSnifferThread.Start;

  FStarted := true;
end;

procedure TSniffer.Stop;
begin
  if FStarted then
  begin
    pcap_close(FPcapHandle);
    FStarted := false;
    FSnifferThread := nil;
  end;
end;

procedure TSniffer.CheckForError(AMethod : String);
var
  I : integer;
begin
  if Length(FPcapErrBuff) > 0 then
    raise TSnifferException.Create(Concat(AMethod, ': ', CharArrayToString(FPcapErrBuff)));

  for I := Low(FPcapErrBuff) to High(FPcapErrBuff) do
    FPcapErrBuff := '';
end;

function TSniffer.CharArrayToString(ACharArray : array of Char) : String;
var
  I : integer;
  Res : string;
begin
  Res := '';
  for I := Low(ACharArray) to High(ACharArray) do
    Res := Res + ACharArray[I];
  CharArrayToString := Res;
end;

function TSniffer.IntegerToDottedDecimal(AWord : DWord) : String;
var
  I : integer;
  C : array[1..4] of String;
begin
  for I := 1 to 4 do
  begin
    C[I] := IntToStr(AWord and ($FF Shr (I * 8)));
  end;
  IntegerToDottedDecimal := Format('%s.%s.%s.%s', [C[1], C[2], C[3], C[4]]);

end;

function TSniffer.GetInterfaceNet : String;
begin
  GetInterfaceNet := IntegerToDottedDecimal(FNet^);
end;

function TSniffer.GetInterfaceMask : String;
begin
  GetInterfaceMask := IntegerToDottedDecimal(FMask^);
end;

function TSniffer.GetSecondsSinceStart : double;
begin
  if FTimeStarted = 0 then
    GetSecondsSinceStart := 0
  else
    GetSecondsSinceStart := MilliSecondsBetween(Now(), FTimeStarted) / 1000;
end;

initialization
  TheSniffer := TSniffer.Create(nil);

end.

