/*
 * QEstEidCommon
 *
 * Copyright (C) 2009 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009 Raul Metsma <raul@innovaatik.ee>
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

#include <QSslCertificate>

#include <QHash>

class SslCertificate: public QSslCertificate
{
public:
	enum KeyUsage
	{
		DigitalSignature = 0,
		NonRepudiation,
		KeyEncipherment,
		DataEncipherment,
		KeyAgreement,
		KeyCertificateSign,
		CRLSign,
		EncipherOnly,
		DecipherOnly,
	};

	SslCertificate( const QSslCertificate &cert );

	QByteArray	authorityKeyIdentifier() const;
	QStringList enhancedKeyUsage() const;
	static QString formatDate( const QDateTime &date, const QString &format );
	static QString formatName( const QString &name );
	static QSslCertificate fromX509( Qt::HANDLE x509 );
	static QSslKey keyFromEVP( Qt::HANDLE evp );
	QString		issuerInfo( SubjectInfo info ) const;
	QString		issuerInfo( const QByteArray &tag ) const;
	bool		isTempel() const;
	bool		isTest() const;
	QHash<int,QString> keyUsage() const;
	QStringList policies() const;
	QString		policyInfo( const QString &oid ) const;
	QString		subjectInfo( SubjectInfo subject ) const;
	QString		subjectInfo( const QByteArray &tag ) const;
	QByteArray	subjectKeyIdentifier() const;
	static QByteArray	toHex( const QByteArray &in, QChar separator = ' ' );
	QString		toString( const QString &format ) const;

#if QT_VERSION < 0x040600
	QByteArray	serialNumber() const;
	QByteArray	version() const;
#endif

private:
	void*	getExtension( int nid ) const;
	QByteArray subjectInfoToString( SubjectInfo info ) const;
	QMap<QString,QString> mapFromOnlineName( const QString &name ) const;
};

class PKCS12CertificatePrivate;
class PKCS12Certificate
{
public:
	enum ErrorType
	{
		InvalidPassword = 1,
		Unknown = -1,
	};
	PKCS12Certificate( QIODevice *device, const QByteArray &pin );
	PKCS12Certificate( const QByteArray &data, const QByteArray &pin );
	~PKCS12Certificate();

	QSslCertificate certificate() const;
	ErrorType error() const;
	QString errorString() const;
	bool isNull() const;
	QSslKey	key() const;

private:
	PKCS12CertificatePrivate *d;
};
