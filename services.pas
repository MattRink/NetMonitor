unit Services;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils,
  Logger;

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

type
  TServiceHandler = class(TObject)
  private
    FLogger : TLogger;

    procedure HandleDNS(APkt : LongWord; ALength : Cardinal);
    procedure HandleHTTP(APkt : LongWord; ALength : Cardinal);
    procedure DoLog(AMessage : String);
  public
    procedure HandleService(APkt : LongWord; ALength : Cardinal; APort : Word);

    property Logger : TLogger read FLogger write FLogger;
  end;

implementation

procedure TServiceHandler.HandleService(APkt : LongWord; ALength : Cardinal; APort : Word);
begin
  case APort of
    PORT_DNS : HandleDNS(APkt, ALength);
    PORT_HTTP, PORT_HTTP_SSL : HandleHTTP(APkt, ALength);
  end;
end;

procedure TServiceHandler.HandleDNS(APkt : LongWord; ALength : Cardinal);
begin
  DoLog('DNS');
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

