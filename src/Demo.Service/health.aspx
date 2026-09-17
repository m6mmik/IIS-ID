<%@ Page Language="C#" %>
<%
    Response.ContentType = "application/json; charset=utf-8";
    Response.Cache.SetCacheability(HttpCacheability.NoCache);
    var site = System.Web.Hosting.HostingEnvironment.SiteName ?? "unknown";
    var pid = System.Diagnostics.Process.GetCurrentProcess().Id;
    Response.Write("{\"status\":\"ok\",\"site\":\"" + site + "\",\"pid\":" + pid + "}");
%>
