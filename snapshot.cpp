// snapshot.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
// only include at src with main(), and place ahead of other includes
#include "env_var.h"
//-----------------------------------------------------------------------------
#include <boost/filesystem.hpp>

#include "utils.h"
#include "db.h"
#include "log.h"
#include "cmd_cfg.h"
#include "sys_cfg.h"
#include "security.h"
#include "search.h"
#include "pkg.h"
//
#include "task_exe.h"

//=============================================================================
using namespace std;
using namespace bw;
namespace bpo = boost::program_options;
//using CmdOptSpec = std::map<string, pair<const bpo::value_semantic*, string>>;
//=============================================================================
class AppCmdOption : public cfg::AppCmdOptionCfg {
 public:
  string entryDB = cfg::readCfg().get<string>(cfg::CfgType::ENTRY_DB_FILE);
  string recordDB = cfg::readCfg().get<string>(cfg::CfgType::RECORD_DB_FILE);
  string lockDB = cfg::readCfg().get<string>(cfg::CfgType::LOCK_DB_FILE);
  string packageDir = cfg::readCfg().get<string>(cfg::CfgType::PACKAGE_DIR);

  utils::StringSC masterPass;
  int blockSize = cfg::readCfg().get<int>(cfg::CfgType::BLOCK_SIZE);
  vector<string> backupTestPath;
  bool listSearchSpace = false;
  bool listSearchFound = false;
  //
  bw::cfg::CmdOptTable cmdOptTable;
  //
  AppCmdOption()
    : AppCmdOptionCfg("Take a snapshot of specified search area defined by "
                      "config settings.")
    , cmdOptTable({
      {"list-search",    NULL,
                         "Display all files/dirs, unfiltered from search spec"},      {"match-file-only",NULL, "Match file only in search space"},
      {"enable-dirlink", NULL, "Enable follow directory link"},
      {"block-size",     bpo::value<int>(&blockSize),
                         "Size of data block when snapshot partitions files. Default: " +
                         std::to_string(blockSize) + 
                         "(" + utils::toUnitByte(blockSize) + ")"},
      {"entry-db",       bpo::value<string>(&entryDB),
                         "File path of snapshot database. Default " + entryDB},
      {"record-db",      bpo::value<string>(&recordDB),
                         "File path of database records of snapshot file entries."
                         "Default: " + recordDB},
      {"lock-db",        bpo::value<string>(&lockDB),
                         "File path of master lock database. Default: " + lockDB},
        }) {
    addOptTable(cmdOptTable);
    // add last position option
    cfg::AppCmdOptionCfg::optDesc.add_options()
      ("path,p",          bpo::value<vector<string>>(&backupTestPath)->multitoken(),
                          "For testing purpose. Because the program only takes "
                          "snapshot of specified files/dirs, it is not considered "
                          "complete snapshot session.");
      cfg::AppCmdOptionCfg::posDesc.add("path,p", -1);
    //
  }
  //---------------------------------------------------------------------------
  // set config settings with app command line option inputs
  bool loadAppCmdSettings() {
    bool fonly, dlnk;
    if (loadCfgFile() == false) {
      return false;
    }
    if (getFlagOpt(fonly, "match-file-only")) {
      cfg::writeCfg().put(cfg::CfgType::MATCH_FILE_ONLY, true);
    }
    if (getFlagOpt(dlnk, "enable-dirlink")) {
      cfg::writeCfg().put(cfg::CfgType::FOLLOW_DIRLINK, true);
    }
    int sz;
    if (getNumberOpt(sz, "block-size")) {
      IF_ERR(sz < cfg::readCfg().get<int>(cfg::CfgType::PKG_BUF_SIZE),
             "block size cannot be bigger than package buffer size",
             return false);
      cfg::writeCfg().put(cfg::CfgType::BLOCK_SIZE, sz);
    }
    string tmp;
    if (getStringOpt(tmp, "entry-db")) {
      IF_ERR(!tmp.empty(), "cannot set entry database file to empty",
             return false);
      cfg::writeCfg().put(cfg::CfgType::ENTRY_DB_FILE, tmp);
    }
    if (getStringOpt(tmp, "record-db")) {
      IF_ERR(!tmp.empty(), "cannot set record database file to empty",
             return false);
      cfg::writeCfg().put(cfg::CfgType::RECORD_DB_FILE, tmp);
    }
    if (getStringOpt(tmp, "lock-db")) {
      IF_ERR(!tmp.empty(), "cannot set key lock database file to empty",
             return false);
      cfg::writeCfg().put(cfg::CfgType::LOCK_DB_FILE, tmp);
    }
    //if (getStringOpt(tmp, "master-pass")) {
    //  cfg::writeCfg().put(cfg::CfgType::MASTER_PASS, tmp);
    //  utils::cleanUp(tmp);
    //}
    listSearchSpace = findOpt("list-search");
    listSearchFound = findOpt("list-found");

    return true;
  }
};
//===========================================================================
string getHomeDir() {
  string hdir = utils::env::getHomePath();
  if (hdir.empty()) {
    IF_WARN(!hdir.empty(), "unable to resolve home dir from environment variable"
            "using current dir instead", hdir = utils::getCurrentDir());
  }
  return hdir;
}
//=============================================================================
//bool setup(AppCmdOption& opt, int argc, char* argv[]) {
template <typename charT>
bool setup(AppCmdOption& opt, int argc, const charT* argv[]) {
  bw::cfg::writeCfg().put(cfg::CfgType::LOG_ENABLED, false);
  //
  if (opt.parse(argc, argv) == false) {
    LOG_ERR("Error in parsing input arguments.\n");
    opt.printHelp();
    return false;
  }
  //
  if ((opt.loadAppCmdSettings() == false)) {
    LOG_ERR("Error in loading configuration\n");
    return false;
  }
  //
  if (opt.getCfgFile().empty()) {
    bw::cfg::writeSchCfg().loadPresetDefault(getHomeDir());
  }
  //
  return true;
}

//=============================================================================
bool printSinkSpec(ostream& oss) {
  const string& pkgdb = cfg::readCfg().get<string>(cfg::CfgType::ENTRY_DB_FILE);
  const string& recdb = cfg::readCfg().get<string>(cfg::CfgType::RECORD_DB_FILE);
  pkg::SnapshotTable sstbl(pkgdb, recdb);
  bool ok = sstbl.sinkPkg.build();
  IF_ERR(ok, "error in building sink pool to list its spec", return false);
  oss << "#Sink pool spec ---------------------------------------------------\n";
  sstbl.sinkPkg.toStreamCfg(oss);
  oss << "#------------------------------------------------------------------\n";
  return ok;
}
//
bool runDispList(bool& dispMode,
                 fs::SearchEngine& sEng,
                 const AppCmdOption& opt) {
  string cfgfn;
  //
  if (opt.printHelp()) {
    return true;
  }
  if (opt.isDispCfg()) {
    sEng.printSpec(cout);
    printSinkSpec(cout);
    return true;
  }
  //
  if (opt.getStringOpt(cfgfn, "dump-cfg")) {
    IF_ERR(!cfgfn.empty(), "file name cannot be empty", return false);
    bool ok = sEng.saveSpec(cfgfn);
    IF_ERR(ok, "fail to dump config settings to file " << cfgfn,
           return false);
    return true;
  }
  if (opt.isDryRun()) {
    for (auto& f : sEng) {
     cout << utils::toStrU8(f.native()) << endl;
    }
    return true;
  }
  dispMode = false;
  return true;
}
//
bool cfgLockCheck(const AppCmdOption& opt) {
  bool ok = cfg::readCfg().snapShotTimeCheck();
  IF_ERR(ok, "config snapshot check failed", return false);
  //
  string lckdb = cfg::readCfg().get<string>(cfg::CfgType::LOCK_DB_FILE);
  sc::MasterLock mlock(lckdb);
  sc::LockManager mngr(mlock);
  ok = mngr.isReadyToUse(false);
  if (!ok) {
    ok = opt.isDryRun() || mngr.prepare();
    IF_ERR(ok, "fail to prepare lock key pair at the first time run",
           return false);
  }
  return true;
}
//
bool runSnapshot(fs::SearchEngine& sEng, const AppCmdOption& opt) {
  bool rc = true;
  bool complete = true;
  const string& entdb = cfg::readCfg().get<string>(cfg::CfgType::ENTRY_DB_FILE);
  const string& recdb = cfg::readCfg().get<string>(cfg::CfgType::RECORD_DB_FILE);
  const string& lckdb = cfg::readCfg().get<string>(cfg::CfgType::LOCK_DB_FILE);
  //
  pkg::SnapshotSession ss(entdb, recdb, lckdb);
  bool ok = opt.isDryRun() || (ss.isOK() && ss.init());
  IF_ERR(ok, "snapshot initialization failed", return false);
  //
  if (opt.backupTestPath.empty()) {
    ok = sEng.build();
    IF_ERR(ok, "fail to build search engine from config", return false);
  } else {
    complete = false;
    ok = sEng.build(utils::PathSet::toNormalize(opt.backupTestPath));
    IF_ERR(ok, "fail to build search engine from input files", return false);
  }
  //
  if (opt.listSearchSpace || opt.listSearchFound) {
    sEng.listAll(std::cout, opt.listSearchFound);
    return rc;
  }
  //
  for (auto& f : sEng) {
    LOG_INFO("Processing : " << utils::toStrU8(f.native()));
    ok = ss.snapshot(f, opt.isDryRun());
    IF_ERR(ok, "error in processing file " << f, rc = false);
  }
  ok = opt.isDryRun() || ss.finalize(complete);
  IF_ERR(ok, "error in snapshot finalization", rc = false);
  return rc;
}
//
//=============================================================================
//
//int main(int argc, char* argv[]) {
#ifdef UNICODE_MAIN
int main(int argc, char* argv[]) {
#else
int wmain(int argc, const wchar_t* argv[]) {
#endif
  bool listMode = true;
  AppCmdOption opt;
  //
  utils::env::addProgramPathToDllSearch();
  //
  bool ok =setup(opt, argc, argv); 
  IF_ERR(ok, "setup failed, abort snapshot session", return 1);
  fs::SearchEngine sEng;
  ok = runDispList(listMode, sEng, opt);
  IF_ERR(ok, "display mode ends in error",           return 2);
  if (!listMode) {
    ok = cfgLockCheck(opt);
    IF_ERR(ok, "detect error in snapshot configure", return 3);
    ok = runSnapshot(sEng, opt);
    IF_ERR(ok, "snapshot session ends in error",     return -1);
  }
  return  0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu
// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
 