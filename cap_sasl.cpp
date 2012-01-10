

Implements SASL Authentication capability for charybdis family ircds

At present this only implements the PLAIN (base64) mechanism,
and as such should be used in conjunction with SSL where security is a
concern.

Usage: "LoadModule cap_sasl <accountname> <passsword>"

TODO: support for the more secure DH-BLOWFISH mechanism

(C)2010 Mike Quin

Licensed under the GNU General Public License

*/

#include "Modules.h"
#include "User.h"
#include "IRCSock.h"

class CSASLMod : public CModule {
public:
  MODCONSTRUCTOR(CSASLMod) {}

  virtual bool OnLoad(const CString& sArgs, CString& sMessage) {
    if (sArgs.Token(0).empty()){
      m_sAccount=GetNV("SASL_Account");
    } else {
      m_sAccount=sArgs.Token(0);
      SetNV("SASL_Account", m_sAccount);
    }

    if (sArgs.Token(1).empty()){
      m_sPass=GetNV("SASL_Password");
    } else {
      m_sPass=sArgs.Token(1);
      SetNV("SASL_Password", m_sPass);
    }
    SetArgs("");
    return true;
  }

  virtual void OnModCommand(const CString& sCommand) 
  { 
    CString sCmdName = sCommand.Token(0).AsLower(); 
    if (sCmdName == "set") { 
      CString sAccount = sCommand.Token(1); 
      CString sPass = sCommand.Token(2, true);  
      m_sPass = sPass; 
      m_sAccount = sAccount; 
      SetNV("SASL_Password", m_sPass); 
      SetNV("SASL_Account", m_sAccount); 
      PutModule("Password set"); 
    } else if (sCmdName == "clear") { 
      m_sPass = ""; 
      DelNV("SASL_Password"); 
      DelNV("SASL_Account"); 
    } else { 
      PutModule("Commands: set <accountname> <password>, clear"); 
    } 
  } 


  virtual ~CSASLMod() {}
    
  virtual bool OnServerCapAvailable(const CString& sCap) {
    return sCap == "sasl";
  }

  virtual void OnServerCapResult(const CString& sCap, const bool state) {
    CIRCSock *pIRCSock = GetUser()->GetIRCSock();
    if (!pIRCSock)
      return;
    if (state == true && sCap == "sasl") {
      pIRCSock->PauseCap();
      PutIRC("AUTHENTICATE PLAIN");
    }
  }
    
  virtual EModRet OnRaw(CString &sLine) {
    CIRCSock *pIRCSock = GetUser()->GetIRCSock();
    if (!pIRCSock)
      return CONTINUE;
    if (sLine.Equals("AUTHENTICATE +") && !m_sAccount.empty() && !m_sPass.empty()) {
      CString authdata = m_sAccount + '\0' + m_sAccount + '\0' + m_sPass;
      authdata.Base64Encode();
      // sasldata.Base64Encode();
      PutIRC("AUTHENTICATE " + authdata);
    } else if (sLine.Token(1).Equals("903") || 
	       sLine.Token(1).Equals("904") || 
	       sLine.Token(1).Equals("905") || 
	       sLine.Token(1).Equals("906") || 
	       sLine.Token(1).Equals("907") ) {
      pIRCSock->ResumeCap();
    }
    return CONTINUE;
  }
    
private:
  CString m_sAccount;
  CString m_sPass;
};

MODULEDEFS(CSASLMod, "Adds support for sasl authentication capability")


