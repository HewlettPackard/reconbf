Recon by fire
=============

Recon is a tool for reviewing the security configuration of a local system. It
can detect existing issues, known-insecure settings, existing strange behaviour,
and options for further hardening.

Recon can be used in existing systems to find out which elements can be improved
and can provide some information about why the change is recommended. It can
also be used to scan prepared system images to verify that they contain the
expected protection.


What can Recon help with
------------------------

Recon checks:

- sysctl settings
- application configs
- security features used in compiled binaries
- security features of current kernel
- suspicious system conditions (like upgraded binaries which have not been
  restarted)
- and many others

Recon is most useful for verifying that the system security is configured as
expected and for spotting hardening opportunities.


What Recon isn't
----------------

System integrity checker - although it can be used to check the results or any
such system.

Rootkit detector - Recon uses only the most strightforward way to verify the
system state. It does not try to detect existing hidden or malicious elements.

Intrusion detection system - it will not attempt to detect active attackers.


Recon usage
-----------

Recon requires root privileges on the system to run most of its tests. All the
system access is readonly however - no changes are made during the run and Recon
should not affect processes on a production system.

::

    usage: reconbf [-h] [-c CONFIG_FILE] [-g {default,inline}]
                   [-l--level {debug,info,error}] [-rf REPORT_FILE]
                   [-rt {csv,json,html}] [-dm {all,fail,overall,notpass}]

    ReconBF - a Python OS security feature tester

    optional arguments:
      -h, --help            show this help message and exit
      -c CONFIG_FILE, --config CONFIG_FILE
                            use specified config file instead of default
      -g {default,inline}, --generate {default,inline}
                            generates config file contetns with all the available
                            modules listed and either configured to use the config
                            that comes with the test, or inlines the current
                            default configuration
      -l--level {debug,info,error}
                            log level: can be "debug", "info", or "error"
                            default=info
      -rf REPORT_FILE, --reportfile REPORT_FILE
                            output file: default=result.out
      -rt {csv,json,html}, --reporttype {csv,json,html}
                            output type: can be "csv", "json", or "html"
      -dm {all,fail,overall,notpass}, --displaymode {all,fail,overall,notpass}
                            controls how tests are displayed: all-displays all
                            results, fail-displays only tests which failed,
                            overall-displays parent test statuses only, notpass-
                            displays any test which didn't pass

The default way to run Recon is just `python -m reconbf` or install it and run
`reconbf` (both with `sudo` if running as a non-root user).

If you need to adjust the configuration or verify your system against only a
specific set of tests, you can generate a new configuration file using `-g
inline` option. The resulting configuration will include all the available
modules and also the default module configuration where needed.


Interpreting results
--------------------

Some tests will result in a very clear answer. For example `test_sysctl_values`
is going to always give the real answer coming from the `sysctl` output.

Other tests may not be that clear, or may be skipped when some system elements
are not reachable. For example `test_ptrace_scope` depends on kernel config
being available on the system and matching the currently deployed kernel. While
this is the usual and expected state, any failures or skipped tests should be
investigated separately and understood before taking actions to correct them.

Other tests may rely on information which is not always available. For example
`test_binaries` will attempt to check whether some binaries were compiled with
stack protection. While this check will not have false-positives, it may report
a false-negative if the analysed binary was compiled with `-fstack-protector`
(not `-fstack-protector-all`) and gcc decides that none of the functions
contained buffers that require protection.
