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

#include <QObject>

#include <common/SslCertificate.h>

class QCSPPrivate;
class TokenData;

class QCSP: public QObject
{
	Q_OBJECT
public:
	enum PinStatus
	{
		PinOK,
		PinCanceled,
		PinUnknown,
	};

	explicit QCSP( QObject *parent = 0 );
	~QCSP();

	QStringList containers( SslCertificate::KeyUsage usage );
	QByteArray decrypt( const QByteArray &data );
	PinStatus lastError() const;
	PinStatus login( const TokenData &t );
	TokenData selectCert( const QString &cert, SslCertificate::KeyUsage usage );
	QByteArray sign( int method, const QByteArray &digest );

private:
	QByteArray reverse( const QByteArray &data ) const;
	QCSPPrivate *d;
};
