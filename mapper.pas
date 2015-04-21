unit Mapper;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, DaemonApp;

type
  TNetMonitorMapper = class(TDaemonMapper)
  private
    { private declarations }
  public
    { public declarations }
  end;

  procedure RegisterMapper;

var
  NetMonitorMapper: TNetMonitorMapper;

implementation

procedure RegisterMapper;
begin
  RegisterDaemonMapper(TNetMonitorMapper)
end;

{$R *.lfm}


initialization
  RegisterMapper;
end.

