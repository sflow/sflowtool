Summary: tool to ascii-print or forward sFlow datagrams
Name: sflowtool
Version: 3.39
Release: 1%{?dist}
License: http://www.inmon.com/technology/sflowlicense.txt
Group: Productivity/Networking/Diagnostic
URL: http://inmon.com/technology/sflowTools.php
Source: http://inmon.com/bin/sflowtool-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
The sFlow toolkit provides command line utilities and scripts for analyzing
sFlow data. sflowtool interfaces to utilities such as tcpdump, Wireshark and Snort
for detailed packet tracing and analysis, NetFlow compatible collectors for IP
flow accounting, and provides text based output that can be used in scripts to
provide customized analysis and reporting and for integrating with other tools
such as Graphite or rrdtool.

%prep

%setup -q -n %{name}-%{version}

%build
%configure \
                --prefix=%{_prefix} \
                --sysconfdir=%{_sysconfdir} \
                --infodir=%{_infodir} \
                --mandir=%{_mandir}
make

%install
make DESTDIR=%{buildroot} install

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
/usr/bin/sflowtool
%doc AUTHORS INSTALL NEWS ChangeLog README

%changelog
* Mon Jun 4 2012 Neil McKee <neil.mckee@inmon.com>> 3.26
Initial spec to build sflowtool RPM
