unit Logger;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, LCLType, Dialogs;

type
  TRecorder = procedure(AMessage : String) of object;

  TRecorderList = class
  private
    FItems : array of TRecorder;

    function GetCount : integer;
  public
    constructor Create;
    procedure Add(ARecorder : TRecorder);
    function Get(AIndex : Integer) : TRecorder;

    property Count : integer read GetCount;
  end;

  TLogger = class(TThread)
  private
    FRunning : boolean;
    FRecorders : TRecorderList;
    FLogQueue : TStringList;
    FCriticalSection : TRTLCriticalSection ;
    FSnifferTerminateEvent : PRTLEvent;
  protected
    procedure Execute; override;
  public
    constructor Create;
    destructor Destroy; override;
    procedure AddRecorder(ARecorder : TRecorder);
    procedure Log(AMessage : String; ALevel : integer = 0);

    property Running : boolean read FRunning;
    property SnifferTerminateEvent : PRTLEvent read FSnifferTerminateEvent;
  end;

const
  LOG_DEBUG     = 0;
  LOG_VERBOSE   = 1;
  LOG_INFO      = 2;
  LOG_ERROR     = 3;
  LOG_WARN      = 4;
  LOG_FATAL     = 5;

implementation

constructor TRecorderList.Create;
begin
  SetLength(FItems, 0);
end;

function TRecorderList.GetCount : integer;
begin
  GetCount := Length(FItems);
end;

procedure TRecorderList.Add(ARecorder : TRecorder);
begin
  SetLength(FItems, Length(FItems) + 1);
  FItems[Length(FItems) - 1] := ARecorder;
end;

function TRecorderList.Get(AIndex : integer) : TRecorder;
begin
  Get := FItems[AIndex];
end;

constructor TLogger.Create;
begin
  FRunning := false;
  FSnifferTerminateEvent := RTLEventCreate;

  FreeOnTerminate := true;

  FLogQueue := TStringList.Create;
  FRecorders := TRecorderList.Create;

  InitCriticalSection(FCriticalSection);

  inherited Create(false);
end;

destructor TLogger.Destroy;
begin
  while FRunning do
    Sleep(10);

  FLogQueue.Free;
  FRecorders.Free;

  DoneCriticalSection(FCriticalSection);

end;

procedure TLogger.Execute;
var
  I, Q : integer;
  Recorder : TRecorder;
  Message : String;
begin
  FRunning := true;

  while (not Terminated) or (FLogQueue.Count > 0) do
  begin
    if (FRecorders.Count = 0) or (FLogQueue.Count = 0) then
    begin
      Sleep(200);
      continue;
    end;

    EnterCriticalsection(FCriticalSection);
    try
      for Message in FLogQueue do
        begin
        for I := 0 to FRecorders.Count - 1 do
        begin
          if (Terminated) then
            break;

          Recorder := FRecorders.Get(I);
          if not (Recorder = nil) then
            Recorder(Message);
        end;
      end;
      FLogQueue.Clear;
    finally
      LeaveCriticalSection(FCriticalSection);
    end;
  end;

  RTLeventWaitFor(FSnifferTerminateEvent);
  FRunning := false;
end;

procedure TLogger.AddRecorder(ARecorder : TRecorder); // TODO: Should include levels that are logged
begin
  FRecorders.Add(ARecorder);
end;

procedure TLogger.Log(AMessage : String; ALevel : integer = 0);
begin
  EnterCriticalsection(FCriticalSection);
  try
    FLogQueue.Add(AMessage); // TODO: Fix to include log level
  finally
    LeaveCriticalsection(FCriticalSection);
  end;
end;

end.

