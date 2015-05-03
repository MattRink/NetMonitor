unit Services;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Math,
  Logger, NetworkUtils;

const
  PORT_SERVICE_MULTIPLEXER     = 1;
  PORT_COMPRESSNET_MANAGEMENT  = 2;
  PORT_COMPRESSNET_COMPRESSION = 3;
  PORT_REMOTE_JOB_ENTRY        = 5;
  PORT_ECHO                    = 7;
  PORT_DISCARD                 = 9;
  PORT_WAKE_ON_LAN             = 9;
  PORT_DAYTIME                 = 13;
  PORT_QOTD                    = 17;
  PORT_MESSAGE_SEND            = 18;
  PORT_FTP_DATA                = 20;
  PORT_FTP_CONTROL             = 21;
  PORT_SSH                     = 22;
  PORT_TELNET                  = 23;
  PORT_SMTP                    = 25;
  PORT_TIME                    = 37;
  PORT_ARPA_HOST_NAME_SERVER   = 42;
  PORT_WINDOWS_INTERNET_NAME   = 42;
  PORT_WHOIS                   = 43;
  PORT_DNS                     = 53;
  PORT_TFTP                    = 69;
  PORT_FINGER                  = 79;
  PORT_HTTP                    = 80;
  PORT_KERBEROS                = 88;
  PORT_POP2                    = 109;
  PORT_POP3                    = 110;
  PORT_IRC_IDENT               = 113;
  PORT_NNTP                    = 119;
  PORT_NTP                     = 123;
  PORT_HTTP_SSL                = 443;

  DNS_QUERY    = 0;
  DNS_RESPONSE = 1;

  DNS_TYPE_A     = $0001;
  DNS_TYPE_NS    = $0002;
  DNS_TYPE_CNAME = $0005;
  DNS_TYPE_SOA   = $0006;
  DNS_TYPE_WKS   = $000B;
  DNS_TYPE_PTR   = $000C;
  DNS_TYPE_MX    = $000F;
  DNS_TYPE_SRV   = $0021;
  DNS_TYPE_A6    = $0026;
  DNS_TYPE_ANY   = $00FF;

  DNS_CLASS_RESERVED   = $0000;
  DNS_CLASS_INTERNET   = $0001;
  DNS_CLASS_UNASSIGNED = $0002;
  DNS_CLASS_CHAOS      = $0003;
  DNS_CLASS_HESIOD     = $0004;


type
  PCharArray = ^TCharArray;
  TCharArray = array of char;
  PByteArray = ^TByteArray;
  TByteArray = array of byte;
  PWord = ^Word;
  PInteger = ^Integer;

  PDNSHeader = ^TDNSHeader;
  TDNSHeader = packed record
    Identification : Word;
    Flags : Word;
    QuestionCount : Word;
    AnswerRRCount : Word;
    AuthorityRRCount : Word;
    AdditionalRRCount : Word;
  end;

  TDNSResourceRecord = record
    Name : String;
    QueryType : Word;
    QueryClass : Word;
    TimeToLive : Integer;
    ResourceDataLength : Word;
    ResourceData : TByteArray;
  end;

  TServiceHandler = class(TObject)
  private
    FLogger : TLogger;

    procedure HandleDNS(APkt : LongWord; ALength : Cardinal);
    procedure HandleHTTP(APkt : LongWord; ALength : Cardinal);
    procedure DoLog(AMessage : String);
  public
    procedure HandleService(APkt : LongWord; ALength : Cardinal; ASourcePort : Word; ADestPort : Word);

    property Logger : TLogger read FLogger write FLogger;
  end;

implementation

function GetBit(AByte : Byte; APosition : Integer) : Integer;
begin
  GetBit := (AByte shr APosition) and $01;
end;

function GetBit(AWord : Word; APosition : Integer) : Integer;
begin
  GetBit := (AWord shr APosition) and $01;
end;

procedure TServiceHandler.HandleService(APkt : LongWord; ALength : Cardinal; ASourcePort : Word; ADestPort : Word);
var
  Port : Word;
begin
  Port := Min(ASourcePort, ADestPort); // TODO: Fix me, not nice

  case Port of
    PORT_DNS : HandleDNS(APkt, ALength);
    PORT_HTTP, PORT_HTTP_SSL : HandleHTTP(APkt, ALength);
  end;
end;

procedure TServiceHandler.HandleDNS(APkt : LongWord; ALength : Cardinal);
var
  DNSHeader : PDNSHeader;
  NamePointer : Word;
  Op, QueryType : String;
  IsQuery : boolean;
  DNSQueryRecord : TDNSResourceRecord;
  DNSAnswerRecords : array of TDNSResourceRecord;
  I, A : integer;

  procedure GetResourceRecordName(var AResourceRecord : TDNSResourceRecord; APointer : LongWord);
  var
    Name : TCharArray;
    NameLabelLength : Byte;
    N : integer;
  begin
    Name := TCharArray(PtrUInt(APointer));
    I := 0;
    while true do
    begin
      NameLabelLength := Byte(Name[I]);
      for N := 1 to NameLabelLength do // Starting at 1 skips the length byte
        AResourceRecord.Name := AResourceRecord.Name + Name[I + N];

      I := I + N + 1;

      if Byte(Name[I]) = 0 then
        break;

      AResourceRecord.Name := AResourceRecord.Name + '.';
    end;
  end;
begin
  DNSHeader := PDNSHeader(APkt);
  DNSHeader^.Identification    := ToHostOrder(DNSHeader^.Identification);
  DNSHeader^.Flags             := ToHostOrder(DNSHeader^.Flags);
  DNSHeader^.QuestionCount     := ToHostOrder(DNSHeader^.QuestionCount);
  DNSHeader^.AnswerRRCount     := ToHostOrder(DNSHeader^.AnswerRRCount);
  DNSHeader^.AuthorityRRCount  := ToHostOrder(DNSHeader^.AuthorityRRCount);
  DNSHeader^.AdditionalRRCount := ToHostOrder(DNSHeader^.AdditionalRRCount);

  IsQuery := GetBit(DNSHeader^.Flags, 15) = DNS_QUERY;

  SetLength(DNSAnswerRecords, DNSHeader^.AnswerRRCount);

  // All dns queries and responses carry query sections

  GetResourceRecordName(DNSQueryRecord, PtrUInt(APkt) + SizeOf(TDNSHeader));
  Inc(I, 1); // Move past the final byte of the name
  DNSQueryRecord.QueryType := ToHostOrder(PWord(PtrUint(APkt) + SizeOf(TDNSHeader) + I)^);
  Inc(I, 2); // Move past the QueryType field
  DNSQueryRecord.QueryClass := ToHostOrder(PWord(PtrUint(APkt) + SizeOf(TDNSHeader) + I)^);
  Inc(I, 2); // Move past the QueryClass field

  if IsQuery then
  begin
    Op := 'Query';
  end
  else
  begin
    Op := 'Response';

    for A := 0 to DNSHeader^.AnswerRRCount do
    begin
      NamePointer := ToHostOrder(PWord(PtrUInt(APkt) + SizeOf(TDNSHeader) + I)^);
      if GetBit(NamePointer, 0) = 1 and GetBit(NamePointer, 1) then
      begin
        NamePointer := NamePointer - $C000; // Remove the two leading bits
        GetResourceRecordName(DNSAnswerRecords[A], PtrUInt(APkt) + NamePointer);
        Inc(I, 2); // Move past name pointer
        DNSAnswerRecords[A].QueryType := ToHostOrder(PWord(PtrUInt(APkt) + SizeOf(TDNSHeader) + I)^);
        Inc(I, 2); // Move past QueryType
        DNSAnswerRecords[A].QueryClass := ToHostOrder(PWord(PtrUInt(APkt) + SizeOf(TDNSHeader) + I)^);
        Inc(I, 2); // Move past QueryClass
        DNSAnswerRecords[A].TimeToLive := ToHostOrder(PInteger(PtrUInt(APkt) + SizeOf(TDNSHeader) + I)^);
        Inc(I, 4); // Move past TimeToLive
        DNSAnswerRecords[A].ResourceDataLength := ToHostOrder(PWord(PtrUInt(APkt) + SizeOf(TDNSHeader) + I)^);
        Inc(I, 2); // Move past ResourceDataLength
        SetLength(DNSAnswerRecords[A].ResourceData, DNSAnswerRecords[A].ResourceDataLength);
        DNSAnswerRecords[A].ResourceData := PByteArray(PtrUInt(APkt) + SizeOf(TDNSHeader) + I)^; // TODO: Fix me, I through an exception...

      end;
    end;
  end;

  case DNSQueryRecord.QueryType of
    DNS_TYPE_A :     QueryType := 'A';
    DNS_TYPE_NS :    QueryType := 'NS';
    DNS_TYPE_CNAME : QueryType := 'CNAME';
    DNS_TYPE_SOA :   QueryType := 'SOA';
    DNS_TYPE_WKS :   QueryType := 'WKS';
    DNS_TYPE_PTR :   QueryType := 'PTR';
    DNS_TYPE_MX :    QueryType := 'MX';
    DNS_TYPE_SRV :   QueryType := 'SRV';
    DNS_TYPE_A6 :    QueryType := 'A6';
    DNS_TYPE_ANY :   QueryType := 'ANY';
    else
      QueryType := 'Unknown';
  end;

  DoLog(Format('DNS %s - %s, Type: %s', [Op, DNSQueryRecord.Name, QueryType]));
end;

procedure TServiceHandler.HandleHTTP(APkt : LongWord; ALength : Cardinal);
begin
  DoLog('HTTP');
end;

procedure TServiceHandler.DoLog(AMessage : String);
begin
  if Assigned(FLogger) then
    FLogger(AMessage);
end;

end.

