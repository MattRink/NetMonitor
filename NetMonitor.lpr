Program NetMonitor;

Uses
{$IFDEF UNIX}{$IFDEF UseCThreads}
  CThreads,
{$ENDIF}{$ENDIF}
  DaemonApp, lazdaemonapp, Mapper, Daemon, Sniffer
  { add your units here };

begin
  Application.Initialize;
  Application.Run;
end.
