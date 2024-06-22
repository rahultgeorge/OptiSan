#include "CoverageUtilities.hh"

using namespace CoverageUtil;
using namespace llvm;

// Coverage data (all gcov files) - only needed for cost estimation
std::map<std::string, GCOVFile *> coverageData;

GCOVFile *createGCOVFile(std::string fileName)
{
    GCOVFile *GF = new GCOVFile;
    std::string InputGCNO = "";
    std::string InputGCDA = "";

    fileName = fileName.substr(0, fileName.length() - 5);
    InputGCNO = fileName + ".gcno";
    InputGCDA = fileName + ".gcda";
    errs() << "Files:" << InputGCNO << " " << InputGCDA << "\n";

    if (InputGCNO.empty())
    {
        report_fatal_error("Need to specify --gcno!");
    }
    ErrorOr<std::unique_ptr<MemoryBuffer>> GCNO_Buff =
        MemoryBuffer::getFileOrSTDIN(InputGCNO);
    if (std::error_code EC = GCNO_Buff.getError())
    {
        report_fatal_error(InputGCNO + ":" + EC.message());
    }

    GCOVBuffer GCNO_GB(GCNO_Buff.get().get());

    if (!GF->readGCNO(GCNO_GB))
    {
        errs() << "Invalid .gcno File!\n";
        report_fatal_error(InputGCNO + ": Invalid .gcno file!");
    }

    if (InputGCDA.empty())
    {
        report_fatal_error("Need to specify --gcda!");
    }

    ErrorOr<std::unique_ptr<MemoryBuffer>> GCDA_Buff =
        MemoryBuffer::getFileOrSTDIN(InputGCDA);
    if (std::error_code EC = GCDA_Buff.getError())
    {
        errs() << "Invalid gcda file\n";
        // report_fatal_error(InputGCDA + ":" + EC.message());
        return nullptr;
    }

    GCOVBuffer GCDA_GB(GCDA_Buff.get().get());
    if (!GF->readGCDA(GCDA_GB))
    {
        errs() << "Invalid gcda file\n";
        //        report_fatal_error(InputGCDA + ": Invalid .gcda file!");
    }

    return GF;
}

bool readCoverageData(std::string programName, std::string monitorName)
{
    std::string fileName;
    std::regex gcnoPattern(std::string(".*") + ".gcno");
    std::string dirPath;
    if (monitorName.empty())
        dirPath = "./COVERAGE/" + programName + "/" + WORKLOAD_TYPE;
    else
        dirPath = "./COVERAGE/" + monitorName + "/" + programName + "/" + WORKLOAD_TYPE;
    std::string path = fs::path(dirPath);
    assert(fs::exists(path) && "Path does not exist");
    GCOVFile *coverageFile = nullptr;
    for (const auto &file : fs::directory_iterator(path))
    {
        fileName = file.path().filename();
        fileName = dirPath + "/" + fileName;
        if (std::regex_match(fileName, gcnoPattern))
        {
            errs() << "GCNO File name:" << file.path().filename() << "\n";
            coverageFile = createGCOVFile(fileName);
            if (coverageFile)
            {
                fileName = fileName.substr(0, fileName.length() - 5);
                fileName = fileName + ".o";
                coverageData[fileName] = coverageFile;
            }
        }
    }
    return false;
}

uint64_t getFunctionExecutionCount(Function *function)
{

    GCOVFile *GF;
    uint64_t count = 0;
    uint64_t gfCount = 0;

    if (!function)
        return count;


    for (auto it = coverageData.begin(); it != coverageData.end(); it++)
    {
        GF = it->second;
        if (auto gcovFunc = GF->getFunction(function))
        {
            gfCount = gcovFunc->getEntryCount();
            // errs() << gfCount << "|" << count << "\n";
            count = count > gfCount ? count : gfCount;
        }
    }

    return count;
}

uint64_t getExecutionCount(Instruction *instruction)
{

    GCOVFile *GF;
    uint64_t count = 0;
    uint64_t gfCount = 0;
    bool foundCovForInstruction = false;
    std::string fileName;
    if (!instruction)
        return count;
    DILocation *loc = instruction->getDebugLoc();
    /*  if (loc)
     {
         fileName = loc->getFileName;
     }

     if (coverageData.find(fileName) != coverageData.end())
     {
         GF = coverageData[fileName];
         if (GF->getFunction(instruction->getFunction()))
         {
             gfCount = GF->getCount(instruction);
             // errs() << gfCount << "|" << count << "\n";
             count = count > gfCount ? count : gfCount;
             foundCovForInstruction = true;
         }
     } */

    for (auto it = coverageData.begin(); it != coverageData.end(); it++)
    {
        GF = it->second;
        if (GF->getFunction(instruction->getFunction()))
        {
            gfCount = GF->getCount(instruction);
            // errs() << gfCount << "|" << count << "\n";
            count = count > gfCount ? count : gfCount;
            foundCovForInstruction = true;
        }
    }

    //    if (count > 0) {
    //        errs() << *instruction << "|" << (instruction->getFunction()->getName()) << "\n";
    //        errs() << "\t\t Instruction execution count " << count << "\n";
    //    }
    if (!foundCovForInstruction)
    {
        errs() << *instruction << "|" << (instruction->getFunction()->getName()) << "\n";
        errs() << "\t\t Instruction coverage not found exiting "
               << "\n";
        errs() << "\t\t\t Using entry coverage  "
               << "\n";
        if (Function *func = instruction->getFunction())
        {
            auto randomInstInEntry = func->getEntryBlock().getFirstNonPHI();
            if (randomInstInEntry)
                gfCount = GF->getCount(instruction);
        }

        // exit(0);
    }
    return count;
}
