/*
 * QDigiDocCrypto
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

#include <QSslCertificate>

#include <libdigidoc/DigiDocDefs.h>
#include <libdigidoc/DigiDocLib.h>
#include <libdigidoc/DigiDocEnc.h>
#include <libdigidoc/DigiDocObj.h>

class CDocument
{
public:
	QString path;
	QString filename;
	QString mime;
	QString size;
};

class CKey
{
public:
	CKey() {}
	CKey( const QSslCertificate &cert ) { setCert( cert ); }
	void setCert( const QSslCertificate &cert );
	bool operator==( const CKey &other ) const { return other.cert == cert; }

	QSslCertificate cert;
	QString id;
	QString name;
	QString recipient;
	QString type;
};

class Poller;

class CryptoDoc: public QObject
{
	Q_OBJECT
public:
	CryptoDoc( QObject *parent = 0 );

	void addFile( const QString &file, const QString &mime );
	bool addKey( const CKey &key );
	void create( const QString &file );
	void clear();
	bool decrypt();
	QList<CDocument> documents();
	bool encrypt();
	QString fileName() const;
	bool isEncrypted() const;
	bool isNull() const;
	bool isSigned() const;
	QList<CKey> keys();
	bool open( const QString &file );
	void removeDocument( int id );
	void removeKey( int id );
	void save();
	bool saveDDoc( const QString &filename );

public Q_SLOTS:
	void saveDocument( int id, const QString &filepath );

Q_SIGNALS:
	void error( const QString &err, int code, const QString &msg );

private Q_SLOTS:
	void setLastError( const QString &err, int code = -1 );

private:
	bool isEncryptedWarning();
	void cleanProperties();
	void deleteDDoc();

	QString			m_ddoc, m_ddocTemp;
	QString			m_fileName;
	DEncEncryptedData *m_enc;
	SignedDoc		*m_doc;
};
