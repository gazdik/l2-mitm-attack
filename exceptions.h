/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        20/04/17
 * @copyright   The MIT License (MIT)
 */

#ifndef PDS_EXCEPTIONS_H
#define PDS_EXCEPTIONS_H

#include <exception>
#include <stdexcept>

class WrongOption : public std::logic_error
{
public:
    explicit WrongOption(const std::string &msg);
    explicit WrongOption(const char *msg);

    virtual ~WrongOption();
};

class NetError: public std::runtime_error
{
public:
    explicit NetError(const std::string &msg);
    explicit NetError(const char *msg);

    virtual ~NetError();
};

class SystemError: public std::runtime_error
{
public:
    explicit SystemError(const std::string &msg);
    explicit SystemError(const char *msg);

    virtual ~SystemError();
};


#endif //PDS_EXCEPTIONS_H
