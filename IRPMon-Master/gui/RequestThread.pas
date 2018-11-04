﻿Unit RequestThread;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

Interface

Uses
  Windows, Classes, SysUtils, Generics.Collections,
  IRPMonDll;

Type
  TRequestThread = Class (TTHread)
  Private
    FConnected : Boolean;
    FEvent : THandle;
    FSemaphore : THandle;
    FMsgCode : Cardinal;
    FCurrentList : TList<PREQUEST_GENERAL>;
    Procedure PortablePostMessage;
    Procedure PostRequestList;
  Protected
    Procedure Execute; Override;
  Public
    Constructor Create(ACreateSuspended:Boolean; AMsgCode:Cardinal); Reintroduce;
    Destructor Destroy; Override;
    Procedure SignalTerminate;
  end;


Implementation

Uses
  Forms, MainForm;

Procedure TRequestThread.PortablePostMessage;
begin
MainFrm.OnRequest(FCurrentList);
end;

Procedure TRequestThread.PostRequestList;
begin
{$IFDEF FPC}
Synchronize(PortablePostMessage);
{$ELSE}
PostMessage(Application.Handle, FMsgCode, 0, lParam(FCurrentList));
{$ENDIF}
end;

Procedure TRequestThread.Execute;
Var
  rq : PREQUEST_GENERAL;
  err : Cardinal;
  otw : Packed Array [0..1] Of THandle;
  l : TList<PREQUEST_GENERAL>;
begin
FreeOnTerminate := False;
l := TList<PREQUEST_GENERAL>.Create;
otw[0] := FSemaphore;
otw[1] := FEvent;
While Not Terminated  Do
  begin
  err := WaitForMultipleObjects(2, @otw, False, 100);
  Case err Of
    WAIT_OBJECT_0 : begin
      rq := AllocMem(SizeOf(REQUEST_GENERAL));
      If Assigned(rq) Then
        begin
        err := IRPMonDllGetRequest(@rq.Header, SizeOf(REQUEST_GENERAL));
        If err = ERROR_SUCCESS Then
          begin
          l.Add(rq);
          If l.Count > 20 Then
            begin
            FCurrentList := l;
            PostRequestList;
            l := TList<PREQUEST_GENERAL>.Create;
            end;
          end;

        If err <> ERROR_SUCCESS Then
          FreeMem(rq);
        end;
      end;
    WAIT_TIMEOUT: begin
      If l.Count > 0 Then
        begin
        FCurrentList := l;
        PostRequestList;
        l := TList<PREQUEST_GENERAL>.Create;
        end;
      end;
    WAIT_OBJECT_0 + 1 : Terminate;
    end;
  end;

l.Free;
end;


Procedure TRequestTHread.SignalTerminate;
begin
SetEvent(FEvent);
end;


Constructor TRequestThread.Create(ACreateSuspended:Boolean; AMsgCode:Cardinal);
Var
  err : Cardinal;
begin
Inherited Create(True);
FConnected := False;
FEvent := 0;
FSemaphore := 0;
FMsgCode := AMsgCode;
FSemaphore := CreateSemaphore(Nil, 0, $7FFFFFFF, Nil);
If FSemaphore = 0 Then
  Raise Exception.Create(Format('CreateSemaphore: %u', [GetLastError]));

FEvent := CreateEvent(Nil, False, False, Nil);
If FEvent = 0 Then
  Raise Exception.Create(Format('CreateEvent: %u', [GetLastError]));

err := IRPMonDllConnect(FSemaphore);
If err <> ERROR_SUCCESS Then
  Raise Exception.Create(Format('IRPMonDllConnect: %u', [err]));

FConnected := True;
If Not ACreateSuspended Then
  Resume;
end;

Destructor TRequestTHread.Destroy;
begin
If FConnected Then
  IRPMonDllDisconnect;

If FEvent <> 0 Then
  FileClose(FEvent);{ *Převedeno z CloseHandle* }

If FSemaphore <> 0 Then
  FileClose(FSemaphore);{ *Převedeno z CloseHandle* }

Inherited Destroy;
end;

End.
