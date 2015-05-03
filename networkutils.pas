unit NetworkUtils;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;


function HardwareAddressToStr(Bytes : array of byte) : string;
function ToHostOrder(AWord : Word) : Word;
function ToHostOrder(ACardinal : Cardinal) : Cardinal;
function ToHostOrder(ALongInt : LongInt) : LongInt;

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

function ToHostOrder(AWord : Word) : Word;
begin
  {$IFDEF ENDIAN_LITTLE}
  ToHostOrder := SwapEndian(AWord);
  {$ELSE}
  ToHostOrder := AWord;
  {$ENDIF}
end;

function ToHostOrder(ASmallInt : SmallInt) : SmallInt;
begin
  {$IFDEF ENDIAN_LITTLE}
  ToHostOrder := SwapEndian(ASmallInt);
  {$ELSE}
  ToHostOrder := ASmallInt;
  {$ENDIF}
end;

function ToHostOrder(ACardinal : Cardinal) : Cardinal;
begin
  {$IFDEF ENDIAN_LITTLE}
  ToHostOrder := SwapEndian(ACardinal);
  {$ELSE}
  ToHostOrder := ACardinal;
  {$ENDIF}
end;

function ToHostOrder(ALongInt : LongInt) : LongInt;
begin
  {$IFDEF ENDIAN_LITTLE}
  ToHostOrder := SwapEndian(ALongInt);
  {$ELSE}
  ToHostOrder := ALongInt;
  {$ENDIF}
end;

end.

