object HookProgressFrm: THookProgressFrm
  Left = 407
  Height = 888
  Top = 382
  Width = 589
  BorderIcons = []
  Caption = 'Progress'
  ClientHeight = 888
  ClientWidth = 589
  Color = clBtnFace
  DesignTimePPI = 192
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  OnClose = FormClose
  OnCreate = FormCreate
  Position = poScreenCenter
  LCLVersion = '1.8.4.0'
  object LowerPanel: TPanel
    Left = 0
    Height = 49
    Top = 839
    Width = 589
    Align = alBottom
    ClientHeight = 49
    ClientWidth = 589
    TabOrder = 0
    object CloseButton: TButton
      Left = 144
      Height = 33
      Top = 6
      Width = 65
      Caption = 'Close'
      Enabled = False
      OnClick = CloseButtonClick
      TabOrder = 0
    end
  end
  object ProgressListView: TListView
    Left = 0
    Height = 839
    Top = 0
    Width = 589
    Align = alClient
    Columns = <    
      item
        Caption = 'Operation'
        Width = 75
      end    
      item
        Caption = 'Type'
        Width = 55
      end    
      item
        Caption = 'Name'
        Width = 150
      end    
      item
        Caption = 'Status'
      end    
      item
        Caption = 'Description'
        Width = 300
      end>
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
    ReadOnly = True
    RowSelect = True
    TabOrder = 1
    ViewStyle = vsReport
    OnAdvancedCustomDrawItem = ProgressListViewAdvancedCustomDrawItem
  end
end
