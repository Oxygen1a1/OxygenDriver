#include "Global.h"

Global* Global::m_pInstance;

Global* Global::GetInstance()
{
	if (m_pInstance == nullptr) {
		
		

		m_pInstance = (Global*)ExAllocatePoolWithTag(NonPagedPool, sizeof(Global), 'Inst');

	}
	return m_pInstance;
}
