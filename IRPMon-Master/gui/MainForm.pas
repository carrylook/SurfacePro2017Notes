Unit MainForm;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

Interface

Uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics,
  Controls, Forms, Dialogs, ComCtrls, Menus,
  Generics.Collections,
  IRPMonDll, RequestListModel, ExtCtrls,
  HookObjects, RequestThread
{$IFNDEF FPC}
  , AppEvnts
{$ENDIF}
  ;

Type
  TMainFrm = Class (TForm)
    MainMenu1: TMainMenu;
    ActionMenuItem: TMenuItem;
    SelectDriversDevicesMenuItem: TMenuItem;
    ExitMenuItem: TMenuItem;
    MonitoringMenuItem: TMenuItem;
    ClearMenuItem: TMenuItem;
    HelpMenuItem: TMenuItem;
    AboutMenuItem: TMenuItem;
    N5: TMenuItem;
    ColumnsMenuItem: TMenuItem;
    PageControl1: TPageControl;
    RequestTabSheet: TTabSheet;
    RequestListView: TListView;
    CaptureEventsMenuItem: TMenuItem;
    N6: TMenuItem;
    RefreshNameCacheMenuItem: TMenuItem;
    RequestMenuItem: TMenuItem;
    RequestDetailsMenuItem: TMenuItem;
    SaveMenuItem: TMenuItem;
    LogSaveDialog: TSaveDialog;
    N1: TMenuItem;
    WatchClassMenuItem: TMenuItem;
    WatchedClassesMenuItem: TMenuItem;
    WatchDriverNameMenuItem: TMenuItem;
    WatchedDriversMenuItem: TMenuItem;
    SortbyIDMenuItem: TMenuItem;
    DriverMenuItem: TMenuItem;
    UnloadOnExitMenuItem: TMenuItem;
    UninstallOnExitMenuItem: TMenuItem;
    Documentation1: TMenuItem;
    Procedure ClearMenuItemClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure CaptureEventsMenuItemClick(Sender: TObject);
    procedure ExitMenuItemClick(Sender: TObject);
    procedure RefreshNameCacheMenuItemClick(Sender: TObject);
    procedure SelectDriversDevicesMenuItemClick(Sender: TObject);
    procedure RequestDetailsMenuItemClick(Sender: TObject);
    procedure AboutMenuItemClick(Sender: TObject);
    procedure SaveMenuItemClick(Sender: TObject);
    procedure WatchClassMenuItemClick(Sender: TObject);
    procedure WatchDriverNameMenuItemClick(Sender: TObject);
    procedure SortbyIDMenuItemClick(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure DriverMenuItemClick(Sender: TObject);
    procedure Documentation1Click(Sender: TObject);
  Private
{$IFDEF FPC}
    FAppEvents: TApplicationProperties;
{$ELSE}
    FAppEvents: TApplicationEvents;
{$ENDIF}
    FModel : TRequestListModel;
    FHookedDrivers : TDictionary<Pointer, TDriverHookObject>;
    FHookedDevices : TDictionary<Pointer, TDeviceHookObject>;
    FHookedDeviceDriverMap : TDictionary<Pointer, Pointer>;
    FRequestTHread : TRequestThread;
    FRequestMsgCode : Cardinal;
    Procedure EnumerateHooks;
    Procedure EnumerateClassWatches;
    Procedure EnumerateDriverNameWatches;
    Procedure OnWatchedClassClick(Sender:TObject);
    Procedure OnWatchedDriverNameClick(Sender:TObject);
    procedure IrpMonAppEventsMessage(var Msg: tagMSG; var Handled: Boolean);
    Procedure IrpMonAppEventsException(Sender: TObject; E: Exception);
    Procedure WriteSettings;
    Procedure ReadSettings;
  Public
    ServiceTask : TDriverTaskObject;
    TaskList : TTaskOperationList;
    Procedure OnRequest(AList:TList<PREQUEST_GENERAL>);
  end;

Var
  MainFrm: TMainFrm;

Implementation

{$R *.dfm}

Uses
  IniFiles, ShellAPI,
  ListModel, HookProgressForm,
  Utils, TreeForm, RequestDetailsForm, AboutForm,
  ClassWatchAdd, ClassWatch, DriverNameWatchAddForm,
  WatchedDriverNames;



Procedure TMainFrm.EnumerateHooks;
Var
  phde : TPair<Pointer, TDeviceHookObject>;
  phdr : TPair<Pointer, TDriverHookObject>;
  hdr : TDriverHookObject;
  hde : TDeviceHookObject;
  err : Cardinal;
  I, J : Integer;
  count : Cardinal;
  dri : PHOOKED_DRIVER_UMINFO;
  tmp : PHOOKED_DRIVER_UMINFO;
  dei : PHOOKED_DEVICE_UMINFO;
begin
err := IRPMonDllDriverHooksEnumerate(dri, count);
If err = ERROR_SUCCESS Then
  begin
  For phde In FHookedDevices Do
    phde.Value.Free;

  FHookedDevices.Clear;
  For phdr In FHookedDrivers Do
    phdr.Value.Free;

  FHookedDrivers.Clear;
  FHookedDeviceDriverMap.Clear;
  tmp := dri;
  For I := 0 To count - 1 Do
    begin
    hdr := TDriverHookObject.Create(tmp.DriverObject, tmp.DriverName);
    hdr.ObjectId := tmp.ObjectId;
    hdr.Hooked := True;
    FHookedDrivers.Add(hdr.Address, hdr);
    dei := tmp.HookedDevices;
    For J := 0 To tmp.NumberOfHookedDevices - 1 Do
      begin
      hde := TDeviceHookObject.Create(dei.DeviceObject, tmp.DriverObject, Nil, dei.DeviceName);
      hde.ObjectId := dei.ObjectId;
      hde.Hooked := True;
      FHookedDevices.Add(hde.Address, hde);
      FHookedDeviceDriverMap.Add(hde.Address, hdr.Address);
      Inc(dei);
      end;

    Inc(tmp);
    end;

  IRPMonDllDriverHooksFree(dri, count);
  end
Else WInErrorMessage('Failed to enumerate hooked objects', err);
end;

Procedure TMainFrm.ExitMenuItemClick(Sender: TObject);
begin
Close;
end;

Procedure TMainFrm.FormClose(Sender: TObject; var Action: TCloseAction);
begin
FAppEvents.Free;
WriteSettings;
taskList.Add(hooLibraryFinalize, serviceTask);
If UnloadOnExitMenuItem.Checked Then
  taskList.Add(hooStop, serviceTask);

If UninstallOnExitMenuItem.Checked Then
  taskList.Add(hooUnhook, serviceTask);

With THookProgressFrm.Create(Application, taskList) Do
  begin
  ShowModal;
  Free;
  end;
end;

Procedure TMainFrm.FormCreate(Sender: TObject);
begin
RequestListView.DoubleBuffered := True;
{$IFNDEF FPC}
FAppEvents := TApplicationEvents.Create(Self);
FAppEvents.OnMessage := IrpMonAppEventsMessage;
FRequestMsgCode := RegisterWindowMessage('IRPMON');
If FRequestMsgCode = 0 Then
  begin
  WinErrorMessage('Failed to register internal message', GetLastError);
  Exit;
  end;
{$ELSE}
FAppEvents := TApplicationProperties.Create(Self);
{$ENDIF}
FAppEvents.OnException := IrpMonAppEventsException;
FHookedDrivers := TDictionary<Pointer, TDriverHookObject>.Create;
FHookedDevices := TDictionary<Pointer, TDeviceHookObject>.Create;
FHookedDeviceDriverMap := TDictionary<Pointer, Pointer>.Create;
FModel := TRequestListModel.Create;
FModel.ColumnUpdateBegin;
FModel.
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctId), Ord(rlmctId), False, 60).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctTime), Ord(rlmctTime)).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctThreadId), Ord(rlmctThreadId), False, 75).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctProcessId), Ord(rlmctProcessId), False, 75).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctIRQL), Ord(rlmctIRQL)).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctRequestType), Ord(rlmctRequestType)).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctDeviceObject), Ord(rlmctDeviceObject)).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctDeviceName), Ord(rlmctDeviceName), True).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctDriverObject), Ord(rlmctDriverObject)).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctDriverName), Ord(rlmctDriverName), True).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctResult), Ord(rlmctResult), False, 75).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctIRPAddress), Ord(rlmctIRPAddress), False, 75).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctIOSBStatus), Ord(rlmctIOSBStatus), False, 75).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctIOSBInformation), Ord(rlmctIOSBInformation), False, 75).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctSubType), Ord(rlmctSubType), False, 100).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctFileObject), Ord(rlmctFileObject), False, 75).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctIRPFlags), Ord(rlmctIRPFlags), False, 75).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctArg1), Ord(rlmctArg1), False, 75).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctArg2), Ord(rlmctArg2), False, 75).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctArg3), Ord(rlmctArg3), False, 75).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctArg4), Ord(rlmctArg4), False, 75).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctPreviousMode), Ord(rlmctPreviousMode)).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctRequestorMode), Ord(rlmctRequestorMode)).
    ColumnAdd(TDriverRequest.GetBaseColumnName(rlmctRequestorPID), Ord(rlmctRequestorPID));
FModel.ColumnUpdateEnd;
FModel.CreateColumnsMenu(ColumnsMenuItem);
FModel.SetDisplayer(RequestListView);
If IRPMonDllInitialized Then
  begin
  EnumerateClassWatches;
  EnumerateDriverNameWatches;
  end
Else begin
  SelectDriversDevicesMenuItem.Enabled := False;
  WatchClassMenuItem.Enabled := False;
  WatchDriverNameMenuItem.Enabled := False;

  CaptureEventsMenuItem.Enabled := False;
  RefreshNameCacheMenuItem.Enabled := False;
  end;

ReadSettings;
end;

Procedure TMainFrm.IrpMonAppEventsException(Sender: TObject; E: Exception);
begin
ErrorMessage(E.Message);
end;

Procedure TMainFrm.OnRequest(AList:TList<PREQUEST_GENERAL>);
Var
  rq : PREQUEST_GENERAL;
begin
FModel.UpdateRequest := AList;
FModel.Update;
For rq In AList Do
  FreeMem(rq);

AList.Free;
end;

Procedure TMainFrm.IrpMonAppEventsMessage(var Msg: tagMSG;
  Var Handled: Boolean);
Var
  rq : PREQUEST_GENERAL;
begin
If Msg.message = FRequestMsgCode Then
  begin
  OnRequest(TList<PREQUEST_GENERAL>(Msg.lParam));
  Handled := True;
  end;
end;

Procedure TMainFrm.AboutMenuItemClick(Sender: TObject);
begin
With TAboutBox.Create(Self) Do
  begin
  ShowModal;
  Free;
  end;
end;

Procedure TMainFrm.CaptureEventsMenuItemClick(Sender: TObject);
Var
  connect : Boolean;
  M : TMenuItem;
begin
M := Sender As TMenuItem;
connect := Not M.Checked;
If connect Then
  begin
  FRequestThread := TRequestTHread.Create(False, FRequestMsgCode);
  M.Checked := connect;
  end
Else begin
  FRequestThread.SignalTerminate;
  FRequestThread.WaitFor;
  FreeAndNil(FRequestTHread);
  M.Checked := connect;
  end;
end;

Procedure TMainFrm.ClearMenuItemClick(Sender: TObject);
begin
FModel.Clear;
end;

Procedure TMainFrm.Documentation1Click(Sender: TObject);
Var
  appDirectory : WideString;
  helpFileName : WideString;
begin
appDirectory := ExtractFileDir(Application.ExeName);
helpFileName := ExtractFilePath(Application.ExeName) + 'IRPMon.chm';
ShellExecuteW(0, 'open', PWideChar(helpFileName), '', PWideChar(AppDirectory), SW_NORMAL);
end;

Procedure TMainFrm.DriverMenuItemClick(Sender: TObject);
Var
  M : TMenuItem;
begin
M := Sender As TMenuItem;
M.Checked := Not M.Checked;
end;

Procedure TMainFrm.RefreshNameCacheMenuItemClick(Sender: TObject);
Var
  err : Cardinal;
begin
err := FModel.RefreshMaps;
If err <> ERROR_SUCCESS Then
  WinErrorMessage('Unable to refresh name cache', err);
end;

Procedure TMainFrm.RequestDetailsMenuItemClick(Sender: TObject);
Var
  rq : TDriverRequest;
begin
rq := FModel.Selected;
If Assigned(rq) Then
  begin
  With TRequestDetailsFrm.Create(Self, rq) Do
    begin
    ShowModal;
    Free;
    end;
  end
Else begin
  If Sender <> RequestListView Then
    WarningMessage('No request selected');
  end;
end;

Procedure TMainFrm.SaveMenuItemClick(Sender: TObject);
Var
  fn : WideString;
begin
If LogSaveDialog.Execute Then
  begin
  fn := LogSaveDialog.FileName;
  If LogSaveDialog.FilterIndex = 1 Then
    fn := ChangeFIleExt(fn, '.log');

  FModel.Sort;
  FModel.SaveToFile(fn);
  end;
end;

Procedure TMainFrm.SelectDriversDevicesMenuItemClick(Sender: TObject);
begin
With TTreeFrm.Create(Self) Do
  begin
  ShowModal;
  Free;
  end;

EnumerateHooks;
end;

Procedure TMainFrm.SortbyIDMenuItemClick(Sender: TObject);
begin
FModel.Sort;
end;

Procedure TMainFrm.WatchClassMenuItemClick(Sender: TObject);
Var
  M : TMenuItem;
  err : Cardinal;
  mCaption : WideString;
begin
err := ERROR_SUCCESS;
With TClassWatchAddFrm.Create(Self) Do
  begin
  ShowModal;
  If Not Cancelled Then
    begin
    err := SelectedClass.Register(Beginning);
    If err = ERROR_SUCCESS Then
      begin
      M := TMenuItem.Create(WatchedClassesMenuItem);
      mCaption := SelectedClass.Name + ' (';
      If SelectedClass.UpperFIlter Then
        mCaption := mCaption + 'upper, '
      Else mCaption := mCaption + 'lower, ';

      If SelectedClass.Beginning Then
        mCaption := mCaption + 'first)'
      Else mCaption := mCaption + 'last)';

      M.Caption := mCaption;
      M.Tag := NativeInt(SelectedClass);
      M.OnClick := OnWatchedClassClick;
      WatchedClassesMenuItem.Add(M);
      WatchedClassesMenuItem.Visible := True;
      WatchedClassesMenuItem.Enabled := True;
      end
    Else WinErrorMessage('Failed to watch the class', err);

    If err <> ERROR_SUCCESS Then
      SelectedClass.Free;
    end;

  Free;
  end;
end;


Procedure TMainFrm.WatchDriverNameMenuItemClick(Sender: TObject);
Var
  M : TMenuItem;
  dn : TWatchableDriverName;
  err : Cardinal;
  ds : DRIVER_MONITOR_SETTINGS;
begin
With TDriverNameWatchAddFrm.Create(Self) DO
  begin
  ShowModal;
  If Not Cancelled Then
    begin
    ds := DriverSettings;
    dn := TWatchableDriverName.Create(DriverName, ds);
    err := dn.Register;
    If err = ERROR_SUCCESS Then
      begin
      M := TMenuItem.Create(WatchedClassesMenuItem);
      M.Tag := NativeInt(dn);
      M.Caption := dn.Name;
      M.OnClick := OnWatchedDriverNameClick;
      WatchedDriversMenuItem.Add(M);
      WatchedDriversMenuItem.Visible := True;
      WatchedDriversMenuItem.Enabled := True;
      end
    Else WinErrorMessage('Failed to watch for the driver name', err);

    If err <> ERROR_SUCCESS Then
      dn.Free;
    end;

  Free;
  end;
end;

Procedure TMainFrm.OnWatchedClassClick(Sender:TObject);
Var
  err : Cardinal;
  wc : TWatchableClass;
  M : TMenuItem;
begin
M := (Sender As TMenuItem);
wc := TWatchableClass(M.Tag);
err := wc.Unregister;
If err = ERROR_SUCCESS Then
  begin
  wc.Free;
  M.Free;
  If WatchedClassesMenuItem.Count = 0 Then
    begin
    WatchedClassesMenuItem.Visible := False;
    WatchedClassesMenuItem.Enabled := False;
    end;
  end
Else WinErrorMessage('Failed to unregister the watched class', err);
end;

Procedure TMainFrm.EnumerateClassWatches;
Var
  M : TMenuItem;
  mCaption : WideString;
  err : Cardinal;
  wc : TWatchableClass;
  wl : TList<TWatchableClass>;
begin
wl := TList<TWatchableClass>.Create;
err := TWatchableClass.Enumerate(wl);
If err = ERROR_SUCCESS Then
  begin
  For wc In wl DO
    begin
    If wc.Registered Then
      begin
      M := TMenuItem.Create(WatchedClassesMenuItem);
      mCaption := wc.Name + ' (';
      If wc.UpperFIlter Then
        mCaption := mCaption + 'upper, '
      Else mCaption := mCaption + 'lower, ';

      If wc.Beginning Then
        mCaption := mCaption + 'first)'
      Else mCaption := mCaption + 'last)';

      M.Caption := mCaption;
      M.Tag := NativeInt(wc);
      M.OnClick := OnWatchedClassClick;
      WatchedClassesMenuItem.Add(M);
      WatchedClassesMenuItem.Visible := True;
      WatchedClassesMenuItem.Enabled := True;
      end
    Else wc.Free;
    end;
  end
Else WinErrorMessage('Failed to enumerate watched classes', err);

wl.Free;
end;

Procedure TMainFrm.OnWatchedDriverNameClick(Sender:TObject);
Var
  err : Cardinal;
  M : TMenuItem;
  dn : TWatchableDriverName;
begin
M := (Sender As TMenuItem);
dn := TWatchableDriverName(M.Tag);
err := dn.Unregister;
If err = ERROR_SUCCESS Then
  begin
  dn.Free;
  M.Free;
  If WatchedDriversMenuItem.Count = 0 Then
    begin
    WatchedDriversMenuItem.Visible := False;
    WatchedDriversMenuItem.Enabled := False;
    end;
  end
Else WinErrorMessage('Failed to unregister the watched driver name', err);
end;

Procedure TMainFrm.EnumerateDriverNameWatches;
Var
  M : TMenuItem;
  dn : TWatchableDriverName;
  err : Cardinal;
  dnl : TList<TWatchableDriverName>;
begin
dnl := TList<TWatchableDriverName>.Create;
err := TWatchableDriverName.Enumerate(dnl);
If err = ERROR_SUCCESS Then
  begin
  For dn In dnl Do
    begin
    M := TMenuItem.Create(WatchedClassesMenuItem);
    M.Tag := NativeInt(dn);
    M.Caption := dn.Name;
    M.OnClick := OnWatchedDriverNameClick;
    WatchedDriversMenuItem.Add(M);
    WatchedDriversMenuItem.Visible := True;
    WatchedDriversMenuItem.Enabled := True;
    end;
  end
Else WinErrorMessage('Failed to enumerate watched driver names', err);

dnl.Free;
end;

Procedure TMainFrm.WriteSettings;
Var
  I, J : Integer;
  c : TListModelColumn;
  iniCOlumnName : WideString;
  iniFile : TIniFile;
begin
Try
  iniFile := TIniFile.Create(ChangeFileExt(Application.ExeName, '.ini'));
  iniFIle.WriteBool('Driver', 'unload_on_exit', UnloadOnExitMenuItem.Checked);
  iniFIle.WriteBool('Driver', 'uninstall_on_exit', UninstallOnExitMenuItem.Checked);
  iniFile.WriteBool('General', 'CaptureEvents', CaptureEventsMenuItem.Checked);
  For I := 0 To FModel.ColumnCount - 1 Do
    begin
    c := FModel.Columns[I];
    iniColumnName := c.Caption;
    For J := 1 To Length(iniColumnName) Do
      begin
      If (iniColumnName[J] = ' ') Then
        iniColumnName[J] := '_';
      end;

    iniFile.WriteBool('Columns', iniColumnName, c.Visible);
    end;
Finally
  iniFile.Free;
  End;
end;

Procedure TMainFrm.ReadSettings;
Var
  I, J : Integer;
  c : TListModelColumn;
  iniCOlumnName : WideString;
  iniFile : TIniFile;
begin
Try
  iniFile := TIniFile.Create(ChangeFileExt(Application.ExeName, '.ini'));
  UnloadOnExitMenuItem.Checked := iniFIle.ReadBool('Driver', 'unload_on_exit', False);
  UninstallOnExitMenuItem.Checked := iniFIle.ReadBool('Driver', 'uninstall_on_exit', True);
  If IRPMonDllInitialized Then
    begin
    CaptureEventsMenuItem.Checked := Not iniFile.ReadBool('General', 'CaptureEvents', False);
    If Not CaptureEventsMenuItem.Checked Then
      CaptureEventsMenuItemClick(CaptureEventsMenuItem)
    Else CaptureEventsMenuItem.Checked := False;
    end;

  FModel.ColumnUpdateBegin;
  For I := 0 To FModel.ColumnCount - 1 Do
    begin
    c := FModel.Columns[I];
    iniColumnName := c.Caption;
    For J := 1 To Length(iniColumnName) Do
      begin
      If (iniColumnName[J] = ' ') Then
        iniColumnName[J] := '_';
      end;

    FModel.ColumnSetVisible(I, iniFile.ReadBool('Columns', iniColumnName, True));
    end;

  FModel.ColumnUpdateEnd;
Finally
  iniFile.Free;
  End;
end;


End.

