<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>My Profile</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<link href="css/style.css" rel="stylesheet" type="text/css" />
<link rel="stylesheet" type="text/css" href="css/coin-slider.css" />
<script type="text/javascript" src="js/cufon-yui.js"></script>
<script type="text/javascript" src="js/droid_sans_400-droid_sans_700.font.js"></script>
<script type="text/javascript" src="js/jquery-1.4.2.min.js"></script>
<script type="text/javascript" src="js/script.js"></script>
<script type="text/javascript" src="js/coin-slider.min.js"></script>

<style type="text/css">
<!--
.style1 {font-size: 30px}
.style2 {
	font-size: 24px;
	color: #d86d5a;
}
.style7 {color: #00FF00}
.style9 {color: #FF0000}
.style11 {color: #666666}
.style12 {font-family: "Times New Roman", Times, serif}
.style13 {font-size: 15px}
-->
</style>
</head>
<body>
<div class="main">
  <div class="header">
    <div class="header_resize">
      <div class="menu_nav">
        <ul>
          <li><a href="index.html"><span>Home Page</span></a></li>
          <li><a href="a_login.jsp"><span>Admin</span></a></li>
          <li class="active"><a href="u_login.jsp"><span>User</span></a></li>
          <li><a href="attacker.jsp"><span>Attacker</span></a></li>
        </ul>
      </div>
      <div class="logo">
        <h1><a href="index.html" class="style1">Detecting Mobile Malicious<br /> Webpages in Real Time</a></h1>
      </div>
      <div class="clr"></div>
      <div class="slider">
        <div id="coin-slider"> <a href="#"><img src="images/slide1.jpg" width="940" height="310" alt="" /> </a> <a href="#"><img src="images/slide2.jpg" width="940" height="310" alt="" /> </a> <a href="#"><img src="images/slide3.jpg" width="940" height="310" alt="" /> </a> </div>
        <div class="clr"></div>
      </div>
      <div class="clr"></div>
    </div>
  </div>
  <div class="content">
    <div class="content_resize">
      <div class="mainbar">
        <div class="article">
          <h1 align="center" class="style2">MY PROFILE</h1>
          <p>&nbsp;</p>

<table width="547" border="1.5" align="center"  cellpadding="0" cellspacing="0"  >
        <%@ include file="connect.jsp" %>
        <%@ page import="org.bouncycastle.util.encoders.Base64"%>
        <%
						
						String user=(String )application.getAttribute("user");
						
						String s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12;
						int i=0;
						try 
						{
						   	String query="select * from user where name='"+user+"'"; 
						   	Statement st=connection.createStatement();
						   	ResultSet rs=st.executeQuery(query);
					   		if ( rs.next() )
					   		{
								i=rs.getInt(1);
								s2=rs.getString(2);//name
								s4=rs.getString(4);//email
								s5=rs.getString(5);
								s6=rs.getString(6);
								s7=rs.getString(7);//dob
								s8=rs.getString(8);
								s9=rs.getString(9);
								s10=rs.getString(10);//loc
								s11=rs.getString(11);//image
								s12=rs.getString(12);
								
								
								
								
								
					%>
        <tr>
          <td width="230" rowspan="6" ><div class="style7" style="margin:10px 13px 10px 13px;" ><a class="#" id="img1" href="#" >
              <input  name="image" type="image" src="u_Pic.jsp?id=<%=i%>" style="width:200px; height:200px;">
          </a></div></td>
        </tr>
		
        <tr>
          <td  width="145" height="40" valign="middle" bgcolor="#95c234" style="color: #2c83b0;"><div align="left" class="style14 style15 style20 style4 style5 style6 style9 style12 style13" style="margin-left:20px;"><strong>Name</strong></div></td>
          <td  width="164" valign="middle" height="40" style="color:#000000;"><div align="left" class="style23 style6 style11 style12 style13" style="margin-left:20px;">
            <%out.println(s2);%>
          </div></td>
        </tr>
		<tr>
          <td  width="145" height="40" valign="middle" bgcolor="#95c234" style="color: #2c83b0;"><div align="left" class="style14 style15 style20 style4 style5 style6 style9 style12 style13" style="margin-left:20px;"><strong>E-Mail</strong></div></td>
          <td  width="164" valign="middle" height="40"><div align="left" class="style23 style6 style11 style12 style13" style="margin-left:20px;">
            <%out.println(s4);%>
          </div></td>
        </tr>
        <tr>
          <td  width="145" height="40" valign="middle" bgcolor="#95c234" style="color: #2c83b0;"><div align="left" class="style14 style15 style20 style4 style5 style6 style9 style12 style13" style="margin-left:20px;"><strong>Mobile</strong></div></td>
          <td  width="164" valign="middle" height="40"><div align="left" class="style23 style6 style11 style12 style13" style="margin-left:20px;">
            <%out.println(s5);%>
          </div></td>
        </tr>
        <tr>
          <td  width="145" height="40" align="left" valign="middle" bgcolor="#95c234" style="color: #2c83b0;"><div align="left" class="style14 style15 style20 style4 style5 style6 style9 style12 style13" style="margin-left:20px;"><strong>Location</strong></div></td>
          <td  width="164" align="left" valign="middle" height="40"><div align="left" class="style23 style6 style11 style12 style13" style="margin-left:20px;">
            <%out.println(s10);%>
          </div></td>
        </tr>
        <tr>
          <td  width="145" height="40" align="left" valign="middle" bgcolor="#95c234" style="color: #2c83b0;"><div align="left" class="style14 style15 style20 style4 style5 style6 style9 style12 style13" style="margin-left:20px;"><strong>Date of Birth</strong></div></td>
          <td  width="164" align="left" valign="middle" height="40"><div align="left" class="style23 style6 style11 style12 style13" style="margin-left:20px;">
            <%out.println(s7);%>
          </div></td>
        </tr>
         <tr>
		  <td></td>
          <td  width="145" height="40" align="left" valign="middle" bgcolor="#95c234" style="color: #2c83b0;"><div align="left" class="style14 style15 style20 style4 style5 style6 style9 style12 style13" style="margin-left:20px;"><strong>Address</strong></div></td>
          <td  width="164" align="left" valign="middle" height="40"><div align="left" class="style23 style6 style11 style12 style13" style="margin-left:20px;">
            <%out.println(s6);%>
          </div></td>
        </tr>
		<tr>
		  <td></td>
          <td  width="145" height="40" align="left" valign="middle" bgcolor="#95c234" style="color: #2c83b0;"><div align="left" class="style14 style15 style20 style4 style5 style6 style9 style12 style13" style="margin-left:20px;"><strong>Gender</strong></div></td>
          <td  width="164" align="left" valign="middle" height="40"><div align="left" class="style23 style6 style11 style12 style13" style="margin-left:20px;">
            <%out.println(s8);%>
          </div></td>
        </tr>
		<tr>
		  <td></td>
          <td  width="145" height="40" align="left" valign="middle" bgcolor="#95c234" style="color: #2c83b0;"><div align="left" class="style14 style15 style20 style4 style5 style6 style9 style12 style13" style="margin-left:20px;"><strong>Pincode</strong></div></td>
          <td  width="164" align="left" valign="middle" height="40"><div align="left" class="style23 style6 style11 style12 style13" style="margin-left:20px;">
            <%out.println(s9);%>
          </div></td>
        </tr>
		
		<tr>
		  <td></td>
          <td  width="145" height="40" align="left" valign="middle" bgcolor="#95c234" style="color: #2c83b0;"><div align="left" class="style14 style15 style20 style9 style4 style5 style6 style12 style13" style="margin-left:20px;"><strong>Status</strong></div></td>
          <td  width="164" align="left" valign="middle" height="40"><div align="left" class="style23 style6 style11 style12 style13" style="margin-left:20px;">
            <%out.println(s12);%>
          </div></td>
        </tr>
        <%
						}
						connection.close();
					}
					catch(Exception e)
					{
						out.println(e.getMessage());
					}
					%>
      </table>

		  <p>&nbsp;</p>
		  <p align="right"><a href="u_main.jsp">Back</a></p>
        </div>
      </div>
      <div class="sidebar">
        <div class="gadget">
          <h2 class="star"><span>User</span> Menu</h2>
          <div class="clr"></div>
          <ul class="sb_menu">
            <li><a href="u_main.jsp"><span>User Main</span></a></li>
            <li><a href="u_login.jsp"><span>Log Out</span></a></li>
          </ul>
        </div>
      </div>
      <div class="clr"></div>
    </div>
  </div>
  <div class="fbg">
    <div class="fbg_resize">
      <div class="col c1">
        <h2><span>Image</span> Gallery</h2>
        <a href="#"><img src="images/gal1.jpg" width="75" height="75" alt="" class="gal" /></a> <a href="#"><img src="images/gal2.jpg" width="75" height="75" alt="" class="gal" /></a> <a href="#"><img src="images/gal3.jpg" width="75" height="75" alt="" class="gal" /></a> <a href="#"><img src="images/gal4.jpg" width="75" height="75" alt="" class="gal" /></a> <a href="#"><img src="images/gal5.jpg" width="75" height="75" alt="" class="gal" /></a> <a href="#"><img src="images/gal6.jpg" width="75" height="75" alt="" class="gal" /></a> </div>
      <div class="clr"></div>
    </div>
  </div>
  <div class="footer">
    <div class="footer_resize">
      <div style="clear:both;"></div>
    </div>
  </div>
</div>
<div align=center></div>
</body>
</html>
