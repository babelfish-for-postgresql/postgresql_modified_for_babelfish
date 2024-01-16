# The PostgreSQL make files exploit features of GNU make that other
# makes do not have. Because it is a common mistake for users to try
# to build Postgres with a different make, we have this make file
# that, as a service, will look for a GNU make and invoke it, or show
# an error message if none could be found.

# If the user were using GNU make now, this file would not get used
# because GNU make uses a make file named "GNUmakefile" in preference
# to "Makefile" if it exists. PostgreSQL is shipped with a
# "GNUmakefile". If the user hasn't run the configure script yet, the
# GNUmakefile won't exist yet, so we catch that case as well.


# AIX make defaults to building *every* target of the first rule.  Start with
# a single-target, empty rule to make the other targets non-default.
all:

all check install installdirs installcheck installcheck-parallel uninstall clean distclean maintainer-clean dist distcheck world check-world install-world installcheck-world:
	@if [ ! -f GNUmakefile ] ; then \
	   if [ -f INSTALL ] ; then \
	     INSTRUCTIONS="INSTALL"; \
	   else \
	     INSTRUCTIONS="README.git"; \
	   fi; \
	   echo "You need to run the 'configure' program first. See the file"; \
	   echo "'$$INSTRUCTIONS' for installation instructions, or visit: " ; \
	   echo "<https://www.postgresql.org/docs/devel/installation.html>" ; \
	   false ; \
	 fi
	@IFS=':' ; \
	 for dir in $$PATH; do \
	   for prog in gmake gnumake make; do \
	     if [ -f $$dir/$$prog ] && ( $$dir/$$prog -f /dev/null --version 2>/dev/null | grep GNU >/dev/null 2>&1 ) ; then \
	       GMAKE=$$dir/$$prog; \
	       break 2; \
	     fi; \
	   done; \
	 done; \
	\
	 if [ x"$${GMAKE+set}" = xset ]; then \
	   echo "Using GNU make found at $${GMAKE}"; \
	   unset MAKELEVEL; \
	   $${GMAKE} $@ ; \
	 else \
	   echo "You must use GNU make to build PostgreSQL." ; \
	   false; \
	 fi

# Targets in the portion below can be used to generate source tarball
# and RPM containing Babelfish dump utilities (bbf_dump/bbf_dumpall).
PACKAGE_NAME = BabelfishDump
SOURCE_TARBALL = $(PACKAGE_NAME).tar.gz
SPECFILE = $(PACKAGE_NAME).spec
BUILD_DIR = build/rpmbuild
DIRS = 'SPECS' 'COORD_SOURCES' 'DATA_SOURCES' 'BUILD' 'RPMS' 'SOURCES' 'SRPMS'

.PHONY: rpm-clean
rpm-clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(PACKAGE_NAME)
	rm -f $(SOURCE_TARBALL)

.PHONY: tarball
tarball: rpm-clean
	mkdir -p $(PACKAGE_NAME)

	cp -p aclocal.m4 $(PACKAGE_NAME)
	cp -p configure* $(PACKAGE_NAME)
	cp -p GNUmakefile* $(PACKAGE_NAME)
	cp -p Makefile $(PACKAGE_NAME)
	cp -rp config src $(PACKAGE_NAME)
	cp COPYRIGHT LICENSE.PostgreSQL $(PACKAGE_NAME)

	tar -czf $(SOURCE_TARBALL) $(PACKAGE_NAME)/*

.PHONY: sources
sources: tarball

ifdef NODEPS
RPMOPT = -ba -v --nodeps
else
RPMOPT = -ba -v
endif

.PHONY: rpm-only
rpm-only:
	mkdir -p $(addprefix $(BUILD_DIR)/,$(DIRS))
	cp $(SPECFILE) $(BUILD_DIR)/SPECS
	cp $(SOURCE_TARBALL) $(BUILD_DIR)/SOURCES
	rpmbuild $(RPMOPT) --define "_topdir `pwd`/$(BUILD_DIR)" $(BUILD_DIR)/SPECS/$(SPECFILE)
	cp $(BUILD_DIR)/RPMS/*/*rpm build

.PHONY: rpm
rpm: sources rpm-only
