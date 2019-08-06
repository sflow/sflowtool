Summary: tool to ascii-print or forward sFlow datagrams
Name: sflowtool
Version: 5.05
Release: 1%{?dist}
License: https://www.inmon.com/technology/sflowlicense.txt
Group: Productivity/Networking/Diagnostic
URL: https://inmon.com/technology/sflowTools.php
Source: https://github.com/sflow/%{name}/releases/download/v%{version}/%{name}-%{version}.tar.gz
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
%configure
make

%install
make DESTDIR=%{buildroot} install

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc AUTHORS NEWS ChangeLog README
%license COPYING
%{_bindir}/sflowtool

%changelog
* Mon Jun 4 2012 Neil McKee <neil.mckee@inmon.com> - 3.26-1
- Initial spec to build sflowtool RPM
