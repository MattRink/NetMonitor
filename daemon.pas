unit Daemon;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, DaemonApp, EventLog,
  Sniffer;

type

   { TNetMonitorThread }
  TNetMonitorThread = Class(TThread)
  private
    FConfigFile : String;
    FLog : TEventLog;
    FSniffer : TSniffer;
  public
    constructor Create(AConfigFile: String; ALog: TEventLog; ATerminate: TNotifyEvent);
    procedure Execute; override;
  end;

  { TNetMonitorDaemon }
  TNetMonitorDaemon = class(TDaemon)
    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleExecute(Sender: TCustomDaemon);
    procedure DataModuleStart(Sender: TCustomDaemon; var OK: Boolean);
    procedure DataModuleStop(Sender: TCustomDaemon; var OK: Boolean);
  private
    { private declarations }
    FConfigFile : String;
    FThread : TNetMonitorThread;
    FLog : TEventLog;
    procedure ThreadStopped(Sender: TObject);
  public
    { public declarations }
  end;

  procedure RegisterDaemon;

var
  NetMonitorDaemon: TNetMonitorDaemon;

implementation

resourcestring
  SErrNoConfigFile = 'No configuration file found';

// Include windows messages for eventlog component.
{$ifdef mswindows}
{$R fclel.res}
{$endif}

procedure RegisterDaemon;
begin
  RegisterDaemonClass(TNetMonitorDaemon)
end;

{$R *.lfm}

{ TNetMonitorThread }
constructor TNetMonitorThread.Create(AConfigFile: String; ALog: TEventLog; ATerminate: TNotifyEvent);
begin
  FConfigFile := AConfigFile;
  FLog := ALog;
  FreeOnTerminate := false;
  OnTerminate := ATerminate;

  inherited Create(false);
end;

procedure TNetMonitorThread.Execute;
begin
  try
     FLog.Info('Creating Sniffer');
     FSniffer := TSniffer.Create(nil);
     FLog.Info('Loading Sniffer config');
     FSniffer.LoadFromConfig(FConfigFile);
     FLog.Info('Setting up Sniffer');
     FSniffer.Setup;
     FLog.Info('Sniffer setup completed');

     repeat
       Sleep(1000 * 10);
       FLog.Info(DateTimeToStr(Now()));
     until Terminated;
  finally
    FSniffer.Free;
  end;
end;

{ TNetMonitorDaemon }
procedure TNetMonitorDaemon.DataModuleCreate(Sender: TObject);
begin
  FLog := Self.Logger;

  FLog.Info('Service Create');

  if Application.HasOption('c', 'config') then
  begin
    FConfigFile := Application.GetOptionValue('c', 'config');
  end
  else
  begin
    FConfigFile := GetAppConfigFile(false, false);
    if not FileExistsUTF8(FConfigFile) then
    begin
      FConfigFile := GetAppConfigFile(true, false);
      if not FileExistsUTF8(FConfigFile) then
        FConfigFile := 'NetMonitor.cfg';
    end;
  end;
end;

procedure TNetMonitorDaemon.DataModuleExecute(Sender: TCustomDaemon);
begin
  FLog.Info('Service Execute');
end;

procedure TNetMonitorDaemon.DataModuleStart(Sender: TCustomDaemon;
  var OK: Boolean);
begin
  FLog.Info('Service Start');

  if (FConfigFile = '') then
    FLog.Error(SErrNoConfigFile);

  OK := (FThread = nil) and (FConfigFile <> '');
  if OK then
    FThread := TNetMonitorThread.Create(FConfigFile, FLog, @ThreadStopped);
end;

procedure TNetMonitorDaemon.DataModuleStop(Sender: TCustomDaemon;
  var OK: Boolean);
var
  I : integer;
begin
  FLog.Info('Service Stop');
  if Assigned(FThread) then
  begin
    FThread.Terminate;
    I := 0;
    while (FThread <> nil) and (I < 50)  do
    begin
      Sleep(100);
      ReportStatus;
    end;
    if (FThread <> nil) then
      FThread.OnTerminate := nil;
  end;
  OK := FThread = nil;
end;

procedure TNetMonitorDaemon.ThreadStopped(Sender: TObject);
begin
  FThread := nil;
end;

initialization
  RegisterDaemon;
end.

