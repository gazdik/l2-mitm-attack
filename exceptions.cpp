/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        20/04/17
 * @copyright   The MIT License (MIT)
 */

#include "exceptions.h"

WrongOption::WrongOption(const std::string &msg) : logic_error(msg)
{
}

WrongOption::WrongOption(const char *msg) : logic_error(msg)
{
}

WrongOption::~WrongOption()
{
}

NetError::NetError(const std::string &msg) : runtime_error(msg)
{
}

NetError::NetError(const char *msg) : runtime_error(msg)
{
}

NetError::~NetError()
{
}

SystemError::SystemError(const std::string &msg) : runtime_error(msg)
{
}

SystemError::SystemError(const char *msg) : runtime_error(msg)
{
}

SystemError::~SystemError()
{
}
