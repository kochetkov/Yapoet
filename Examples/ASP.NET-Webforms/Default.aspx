<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="PaddingOracleExample.Application.Default" EnableEventValidation = "false" EnableViewState="False"%>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
    <div>
        <h2>Padding Oracle vulnerability example</h2>
        <asp:HiddenField ID="EncryptedAnswer" runat="server" />
        <asp:Label ID="Result" runat="server" Text="Label" Visible="False"></asp:Label><br/>
        <asp:Label ID="Question" runat="server" Text="Label"></asp:Label><br/>
        <asp:TextBox ID="Answer" runat="server"></asp:TextBox>
        <asp:Button ID="SendButton" runat="server" Text="Send" />
    </div>
    </form>
</body>
</html>
