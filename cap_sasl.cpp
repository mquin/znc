/*

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
    if (!sArgs.Token(0).empty()){
      m_sAccount=sArgs.Token(0);
    }
    if (!sArgs.Token(1).empty()){
      m_sPass=sArgs.Token(1);
    }
    return true;
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


