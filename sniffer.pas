unit Sniffer;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils,
  INIFiles, Sockets, DateUtils,
  Pcap,
  Logger, Services, NetworkUtils;

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

  TCP_PROTOCOL_ICMP   = 1;
  TCP_PROTOCOL_IGMP   = 2;
  TCP_PROTOCOL_TCP    = 6;
  TCP_PROTOCOL_UDP    = 17;
  TCP_PROTOCOL_ENCAP  = 41;
  TCP_PROTOCOL_OSPF   = 89;
  TCP_PROTOCOL_SCTP   = 132;

  ARP_REQUEST = 1;
  ARP_REPLY   = 2;

type
  TErrBuff = array[0..PCAP_ERRBUF_SIZE] of Char;

  TSnifferException = class(Exception);

  TSnifferHandler = procedure(ASecondsSinceStart : double; ALength : integer) of object;

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

  PTCPHeader = ^TTCPHeader;
  TTCPHeader = packed record
    DestinationPort : Word;
    SourcePort : Word;
    SequenceNumber : LongInt;
    AcknowledgementNumber : LongInt;
    DataOffsetFlags : SmallInt;
    WindowSize : SmallInt;
    Checksum : SmallInt;
    Urgent : SmallInt;
    OptionPadding : Cardinal;
  end;

  PUDPHeader = ^TUDPHeader;
  TUDPHeader = packed record
    DestinationPort : Word;
    SourcePort : Word;
    Length : Word;
    Checksum : Word;
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
    FLogger : TLogger;
    FServiceHandler : TServiceHandler;
  public
    constructor Create;
    procedure DoLog(AMessage : String);
    procedure HandleARP(APkt : LongWord; ALength : Cardinal);
    procedure HandleIPv4(APkt : LongWord; ALength : Cardinal);
    procedure HandleTCP(APkt : LongWord; ALength : Cardinal);
    procedure HandleUDP(APkt : LongWord; ALength : Cardinal);

    property Logger : TLogger read FLogger write FLogger;
    property ServiceHandler : TServiceHandler read FServiceHandler write FServiceHandler;
  end;

  TSniffer = class;

  TSnifferThread = class(TThread)
  private
    FRunning : boolean;
    FPcapHandle : PPcap;
    FSniffer : TSniffer;
    FSnifferHandler : TSnifferHandler;
    FLogger : TLogger;
    FPacketHandler : TPacketHandler;
    FServiceHandler : TServiceHandler;

    procedure SetLogger(ALogger : TLogger);
  public
    constructor Create(ASniffer : TSniffer; APcapHandle : PPcap; ASnifferHandler : TSnifferHandler);
    procedure Execute; override;
    procedure DoLog(AMessage : String);

    property Running : boolean read FRunning;
    property Logger : TLogger read FLogger write SetLogger;
    property PacketHandler : TPacketHandler read FPacketHandler write FPacketHandler;
    property ServiceHandler : TServiceHandler read FServiceHandler write FServiceHandler;
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
    FPacketHandler : TPacketHandler;
    FServiceHandler : TServiceHandler;
    FSnifferLogger : TLogger;
    FSnifferThread : TSnifferThread;
    FStarted : boolean;
    FTimeStarted : TDateTime;

    procedure DoLog(AMessage : String);
    procedure CheckForPcapError(AMethod : String);
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
    property PacketHandler : TPacketHandler read FPacketHandler;
    property ServiceHandler : TServiceHandler read FServiceHandler;
    property Logger : TLogger read FSnifferLogger write FSnifferLogger;
    property InterfaceNet : String read GetInterfaceNet;
    property InterfaceMask : String read GetInterfaceNet;
    property SecondsSinceStart : double read GetSecondsSinceStart;
  end;

implementation

constructor TPacketHandler.Create();
begin

end;

procedure TPacketHandler.DoLog(AMessage : String);
begin
  if Assigned(FLogger) then
    FLogger.Log(AMessage);
end;

procedure TPacketHandler.HandleARP(APkt : LongWord; ALength : Cardinal);
var
  ARPHeader : PARPHeader;
  Op : String;
begin
  ARPHeader := PARPHeader(APkt);

  ARPHeader^.HardwareType := ToHostOrder(ARPHeader^.HardwareType);
  ARPHeader^.ProtocolType := ToHostOrder(ARPHeader^.ProtocolType);
  ARPHeader^.OperationCode := ToHostOrder(ARPHeader^.OperationCode);

  case ARPHeader^.OperationCode of
    ARP_REQUEST : Op := 'Request';
    ARP_REPLY   : Op := 'Reply';
    else
      Op := 'Unknown';
  end;

  DoLog(Format('ARP %s - Sender: %s (%s), Target: %s (%s)',
    [Op,
     NetAddrToStr(ARPHeader^.SenderIPAddress), HardwareAddressToStr(ARPHeader^.SenderHardwareAddress.Bytes),
     NetAddrToStr(ARPHeader^.TargetIPAddress), HardwareAddressToStr(ARPHeader^.TargetHardwareAddress.Bytes)]));
end;

procedure TPacketHandler.HandleIPv4(APkt : LongWord; ALength: Cardinal);
var
  IPv4Header : PIPv4Header;
  HeaderLength : DWord;
begin
  IPv4Header := PIPv4Header(APkt);

  IPv4Header^.TotalLength := ToHostOrder(IPv4Header^.TotalLength);
  IPv4Header^.Identification := ToHostOrder(IPv4Header^.Identification);
  IPv4Header^.FlagsFO := ToHostOrder(IPv4Header^.FlagsFO);
  IPv4Header^.CRC := ToHostOrder(IPv4Header^.CRC);
  IPv4Header^.OptionPadding := ToHostOrder(IPv4Header^.OptionPadding);

  HeaderLength := Round(((IPv4Header^.VersionIHL and $F) * 32) / 8);

  DoLog(Format('IPv4 - Source: %s, Destination: %s', [NetAddrToStr(IPv4Header^.SourceIP), NetAddrToStr(IPv4Header^.DestinationIP)]));

  case IPv4Header^.Protocol of
    TCP_PROTOCOL_TCP  : HandleTCP(PtrUInt(APkt) + HeaderLength, ALength - HeaderLength);
    TCP_PROTOCOL_UDP  : HandleUDP(PtrUInt(APkt) + HeaderLength, ALength - HeaderLength);
    TCP_PROTOCOL_ICMP : DoLog('ICMP Recived');
  else
    DoLog(Format('Unknown IPv4 protocol %d', [IPv4Header^.Protocol]));
  end;
end;

procedure TPacketHandler.HandleTCP(APkt : LongWord; ALength : Cardinal);
var
  TCPHeader : PTCPHeader;
  HeaderLength : DWord;
begin
  TCPHeader := PTCPHeader(APkt);

  DoLog(Format('TCP - Source Port: %d, Destination Port: %d', [TCPHeader^.SourcePort, TCPHeader^.DestinationPort]));

  HeaderLength := Round(((TCPHeader^.DataOffsetFlags and $F) * 32) / 8);

  if Assigned(FServiceHandler) then
    FServiceHandler.HandleService(PtrUInt(APkt) + HeaderLength, ALength - HeaderLength, TCPHeader^.SourcePort, TCPHeader^.DestinationPort);
end;

procedure TPacketHandler.HandleUDP(APkt : LongWord; ALength : Cardinal);
var
  UDPHeader : PUDPHeader;
  HeaderLength : DWord;
begin
  UDPHeader := PUDPHeader(APkt);

  DoLog(Format('UDP - Source Port: %d, Destination Port: %d', [UDPHeader^.SourcePort, UDPHeader^.DestinationPort]));

  HeaderLength := 8;

  if Assigned(FServiceHandler) then
    FServiceHandler.HandleService(PtrUInt(APkt) + HeaderLength, ALength - HeaderLength, UDPHeader^.SourcePort, UDPHeader^.DestinationPort);
end;

constructor TSnifferThread.Create(ASniffer : TSniffer; APcapHandle : PPcap; ASnifferHandler : TSnifferHandler);
begin
  FRunning := false;
  FSniffer := ASniffer;
  FPcapHandle := APcapHandle;
  FSnifferHandler := ASnifferHandler;
  FreeOnTerminate := false;

  inherited Create(true);
end;

procedure TSnifferThread.Execute;
var
  Res : Integer;
  PktHeader : PPcap_Pkthdr;
  Pkt : PPChar;
  Len : Cardinal;
  EthernetHeader : PEthernetHeader;
begin
  FRunning := true;

  DoLog('Starting sniffer thread');

  while not Terminated do
  begin
    Res := pcap_next_ex(FPcapHandle, @PktHeader, @Pkt);
    if Res = 0 then
    begin
      continue;
    end
    else if Res < 0 then
    begin
      DoLog(Format('Res = %d, breaking', [Res]));
      break;
    end;

    Len := PktHeader^.caplen;
    FSniffer.Handler(FSniffer.SecondsSinceStart, Len);

    if FSniffer.LinkType = DATALINK_ETHERNET then
    begin
      EthernetHeader := PEthernetHeader(Pkt);
      EthernetHeadeR^.EthernetType := ToHostOrder(EthernetHeader^.EthernetType);

      DoLog(Format('Ethernet - %s -> %s', [HardwareAddressToStr(EthernetHeader^.SourceHost.Bytes), HardwareAddressToStr(EthernetHeader^.DestinationHost.Bytes)]));

      case EthernetHeader^.EthernetType of
        ETHERTYPE_IPV4 :
          begin
            if Assigned(FPacketHandler) then
              FPacketHandler.HandleIPv4(PtrUInt(Pkt) + SizeOf(TEthernetHeader), Len - SizeOf(TEthernetHeader))
            else
              DoLog('No packet handler assigned');
          end;
        ETHERTYPE_IPV6 : DoLog('IPv6');
        ETHERTYPE_ARP  :
          begin
            if Assigned(FPacketHandler) then
              FPacketHandler.HandleARP(PtrUInt(Pkt) + SizeOf(TEthernetHeader), Len - SizeOf(TEthernetHeader))
            else
              DoLog('No packet handler assigned');
          end;
      else
        DoLog('Other: ' + Format('%.2x', [EthernetHeader^.EthernetType]));
      end;
    end;

  end;

  DoLog('Finished sniffing');

  FRunning := false;
end;

procedure TSnifferThread.SetLogger(ALogger : TLogger);
begin
  FLogger := ALogger;
end;

procedure TSnifferThread.DoLog(AMessage : String);
begin
  if Assigned(FLogger) then
    FLogger.Log(Format('%s', [AMessage]));
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
    FSnifferLogger.Log(Format('%s', [AMessage]));
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

  DoLog(StrPas(PcapLibVersion));

  if FDevice = '' then
  begin
    FDevice := pcap_lookupdev(FPcapErrBuff);
    if not Assigned(FDevice) then
      CheckForPcapError('pcap_lookupdev');
  end;

  if pcap_lookupnet(FDevice, @FNet, @FMask, FPcapErrBuff) = -1 then
    CheckForPcapError('pcap_lookupnet');

  if pcap_findalldevs(@AllDevs, FPcapErrBuff) = -1 then
    CheckForPcapError('pcap_findalldevs');

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
        DoLog('Broadcast address: ' + NetAddrToStr(DevAddr^.broadaddr^.sin_addr));
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
    CheckForPcapError('pcap_open_live');
  end;

  FLinkType := pcap_datalink(FPcapHandle);
  DoLog('Device is of linktype ' + StrPas(pcap_datalink_val_to_description(LinkType)));

  FTimeStarted := Now();

  FPacketHandler := TPacketHandler.Create;
  FPacketHandler.Logger := FSnifferLogger;
  FServiceHandler := TServiceHandler.Create;
  FServiceHandler.Logger := FSnifferLogger;

  FPacketHandler.ServiceHandler := FServiceHandler;

  FSnifferThread := TSnifferThread.Create(self, FPcapHandle, FSnifferHandler);
  FSnifferThread.Logger := FSnifferLogger;
  FSnifferThread.PacketHandler := FPacketHandler;
  FSnifferThread.ServiceHandler := FServiceHandler;
  FSnifferThread.Start;

  FStarted := true;
end;

procedure TSniffer.Stop;
begin
  if FStarted then
  begin
    try
      FSnifferThread.Terminate;

      FSnifferThread.Free;
      FSnifferThread := nil;

      FServiceHandler.Free;
      FPacketHandler.Free;
    except
      on E : Exception do
        DoLog(E.Message);
    end;

    RTLeventSetEvent(FSnifferLogger.SnifferTerminateEvent);

    pcap_close(FPcapHandle);
    FStarted := false;
  end;
end;

procedure TSniffer.CheckForPcapError(AMethod : String);
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

end.

