/*
 * QDigiDocClient
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

#include <QObject>

#include <QSslCertificate>
#include <QStringList>
#include <QVariant>

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
class QSigner;

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
	void parseExceptionStrings( const digidoc::Exception &e, QStringList &causes );

	const digidoc::Signature *s;
	QString m_lastError;
	DigiDoc *m_parent;
};

class DigiDoc: public QObject
{
	Q_OBJECT
public:
	enum ConfParameter
	{
		PKCS11Module,
		ProxyHost,
		ProxyPort,
		ProxyUser,
		ProxyPass,
		PKCS12Cert,
		PKCS12Pass,
	};

	DigiDoc( QObject *parent = 0 );
	~DigiDoc();

	QString activeCard() const;
	void addFile( const QString &file );
	void create( const QString &file );
	void clear();
	QList<digidoc::Document> documents();
	QString fileName() const;
	bool init();
	bool isNull() const;
	QString lastError() const;
	bool open( const QString &file );
	QStringList presentCards() const;
	void removeDocument( unsigned int num );
	void removeSignature( unsigned int num );
	void save();
	static QString getConfValue( ConfParameter parameter, const QVariant &value = QVariant() );
	static void setConfValue( ConfParameter parameter, const QVariant &value );
	bool sign(
		const QString &city,
		const QString &state,
		const QString &zip,
		const QString &country,
		const QString &role,
		const QString &role2 );
	QSslCertificate signCert();
	QSigner *signer() const;
	bool signMobile( const QString &fName );
	QList<DigiDocSignature> signatures();
	digidoc::WDoc::DocumentType documentType();
	QByteArray getFileDigest( unsigned int i );

Q_SIGNALS:
	void dataChanged();
	void error( const QString &err );

private Q_SLOTS:
	void dataChanged( const QStringList &cards, const QString &card,
		const QSslCertificate &sign );
	void selectCard( const QString &card );
	void setLastError( const QString &err );

private:
	bool checkDoc( bool status = false, const QString &msg = QString() );
	bool parseException( const digidoc::Exception &e, QStringList &causes, digidoc::Exception::ExceptionCode &code );
	void setLastError( const digidoc::Exception &e );

	digidoc::WDoc	*b;
	QSigner			*m_signer;
	QSslCertificate	m_signCert;
	QStringList		m_cards;
	QString			m_card;
	QString			m_fileName;
	QString			m_lastError;
};
