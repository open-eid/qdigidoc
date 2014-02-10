/*
 * QDigiDocClient
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#pragma once

#include <QtCore/QThread>
#include <digidocpp/crypto/Signer.h>

class QMutex;
class QSignerPrivate;
class TokenData;

class QSigner: public QThread, public digidoc::Signer
{
	Q_OBJECT

public:
	enum ApiType
	{
		PKCS11,
		CAPI,
		CNG
	};
	enum ErrorCode
	{
		PinCanceled,
		PinIncorrect,
		PinLocked,
		DecryptFailed,
		DecryptOK
	};
	explicit QSigner( ApiType api, QObject *parent = 0 );
	~QSigner();

	ApiType apiType() const;
	digidoc::X509Cert cert() const;
	ErrorCode decrypt( const QByteArray &in, QByteArray &out );
	Qt::HANDLE handle() const;
	void lock();
	void sign( const std::string &method, const std::vector<unsigned char> &digest,
		std::vector<unsigned char>& signature );
	TokenData tokenauth() const;
	TokenData tokensign() const;
	void unlock();

Q_SIGNALS:
	void authDataChanged( const TokenData &token );
	void signDataChanged( const TokenData &token );
	void error( const QString &msg );

private Q_SLOTS:
	void selectAuthCard( const QString &card );
	void selectSignCard( const QString &card );
	void showWarning( const QString &msg );

private:
	void reloadauth();
	void reloadsign();
	void run();
	void throwException( const QString &msg, digidoc::Exception::ExceptionCode code, int line );

	QSignerPrivate *d;
};
