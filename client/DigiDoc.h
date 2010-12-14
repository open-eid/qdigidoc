/*
 * QDigiDocClient
 *
 * Copyright (C) 2009,2010 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009,2010 Raul Metsma <raul@innovaatik.ee>
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

#include <digidocpp/WDoc.h>

namespace digidoc
{
	class Document;
	class Exception;
	class Signer;
	class Signature;
}

class DigiDoc;
class QDateTime;
class QSslCertificate;
class QStringList;

class DigiDocSignature
{
public:
	enum SignatureStatus
	{
		Valid,
		Invalid,
		Unknown,
	};
	enum SignatureType
	{
		BESType,
		TMType,
		TSType,
		DDocType,
		UnknownType,
	};
	DigiDocSignature( const digidoc::Signature *signature, DigiDoc *parent );

	QSslCertificate	cert() const;
	QDateTime	dateTime() const;
	QString		digestMethod() const;
	QByteArray	digestValue() const;
	SignatureStatus validate();
	QString		lastError() const;
	QString		location() const;
	QStringList locations() const;
	QString		mediaType() const;
	QSslCertificate ocspCert() const;
	DigiDoc		*parent() const;
	QString		role() const;
	QStringList	roles() const;
	SignatureType type() const;

private:
	void setLastError( const digidoc::Exception &e );
	int parseException( const digidoc::Exception &e );
	void parseExceptionStrings( const digidoc::Exception &e,
		QStringList &causes, int &ddocError, QString &ddocMsg );

	const digidoc::Signature *s;
	QString m_lastError;
	DigiDoc *m_parent;
};

class DigiDoc: public QObject
{
	Q_OBJECT
public:
	DigiDoc( QObject *parent = 0 );
	~DigiDoc();

	void addFile( const QString &file );
	void create( const QString &file );
	void clear();
	QList<digidoc::Document> documents();
	QString fileName() const;
	bool isNull() const;
	bool open( const QString &file );
	void removeDocument( unsigned int num );
	void removeSignature( unsigned int num );
	void save();
	bool sign(
		const QString &city,
		const QString &state,
		const QString &zip,
		const QString &country,
		const QString &role,
		const QString &role2 );
	bool signMobile( const QString &fName );
	QList<DigiDocSignature> signatures();
	digidoc::WDoc::DocumentType documentType();
	QByteArray getFileDigest( unsigned int i );

	static bool parseException( const digidoc::Exception &e, QStringList &causes,
		digidoc::Exception::ExceptionCode &code, int &ddocError, QString &ddocMsg );

Q_SIGNALS:
	void error( const QString &msg, int err = -1, const QString &ddocMsg = QString() );

private:
	bool checkDoc( bool status = false, const QString &msg = QString() );
	void setLastError( const digidoc::Exception &e );

	digidoc::WDoc	*b;
	QString			m_fileName;
};
