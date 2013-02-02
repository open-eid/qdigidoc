/*
 * QDigiDocClient
 *
 * Copyright (C) 2009-2012 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2012 Raul Metsma <raul@innovaatik.ee>
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

#include <QtCore/QAbstractTableModel>

#include <digidocpp/ADoc.h>

class DigiDoc;
class QDateTime;
class QSslCertificate;
class QStringList;

class DocumentModel: public QAbstractTableModel
{
	Q_OBJECT
public:
	enum Columns
	{
		Name = 0,
		Mime = 1,
		Size = 2,
		Save = 3,
		Remove = 4,
		Id = 5,

		NColumns
	};

	int columnCount( const QModelIndex &parent = QModelIndex() ) const;
	QVariant data( const QModelIndex &index, int role = Qt::DisplayRole ) const;
	Qt::ItemFlags flags( const QModelIndex &index ) const;
	QMimeData *mimeData( const QModelIndexList &indexes ) const;
	QStringList mimeTypes() const;
	bool removeRows( int row, int count, const QModelIndex &parent = QModelIndex() );
	int rowCount( const QModelIndex &parent = QModelIndex() ) const;

	QString copy( const QModelIndex &index, const QString &path ) const;
	QString mkpath( const QModelIndex &index, const QString &path ) const;

public Q_SLOTS:
	void open( const QModelIndex &index );

private:
	digidoc::DataFile document( const QModelIndex &index ) const;
	DocumentModel( DigiDoc *doc );
	Q_DISABLE_COPY(DocumentModel)

	DigiDoc *d;

	friend class DigiDoc;
};

class DigiDocSignature
{
public:
	enum SignatureStatus
	{
		Valid,
		Invalid,
		Unknown
	};
	enum SignatureType
	{
		BESType,
		TMType,
		TSType,
		DDocType,
		UnknownType
	};
	DigiDocSignature( const digidoc::Signature *signature, DigiDoc *parent );

	QSslCertificate	cert() const;
	QDateTime	dateTime() const;
	bool		isTest() const;
	QString		lastError() const;
	int			lastErrorCode() const;
	QString		location() const;
	QStringList	locations() const;
	QString		mediaType() const;
	QSslCertificate ocspCert() const;
	QString		ocspDigestMethod() const;
	QByteArray	ocspDigestValue() const;
	QByteArray	ocspNonce() const;
	QDateTime	ocspTime() const;
	DigiDoc		*parent() const;
	QString		role() const;
	QStringList	roles() const;
	QString		signatureMethod() const;
	QDateTime	signTime() const;
	SignatureType type() const;
	SignatureStatus validate() const;
	bool		weakDigestMethod() const;

private:
	void setLastError( const digidoc::Exception &e ) const;
	int parseException( const digidoc::Exception &e ) const;

	const digidoc::Signature *s;
	mutable QString m_lastError;
	mutable int m_lastErrorCode;
	DigiDoc *m_parent;
};

class DigiDoc: public QObject
{
	Q_OBJECT
public:
	explicit DigiDoc( QObject *parent = 0 );
	~DigiDoc();

	void addFile( const QString &file );
	bool addSignature( const QByteArray &signature );
	void create( const QString &file );
	void clear();
	DocumentModel *documentModel() const;
	QString fileName() const;
	bool isNull() const;
	bool isSupported() const;
	QString newSignatureID() const;
	bool open( const QString &file );
	void removeSignature( unsigned int num );
	void save( const QString &filename = QString() );
	bool sign(
		const QString &city,
		const QString &state,
		const QString &zip,
		const QString &country,
		const QString &role,
		const QString &role2 );
	QList<DigiDocSignature> signatures();
	digidoc::ADoc::DocumentType documentType() const;
	QByteArray getFileDigest( unsigned int i ) const;

	static bool parseException( const digidoc::Exception &e, QStringList &causes,
		digidoc::Exception::ExceptionCode &code, int &ddocError );

private:
	bool checkDoc( bool status = false, const QString &msg = QString() ) const;
	void setLastError( const QString &msg, const digidoc::Exception &e );

	digidoc::ADoc	*b;
	QString			m_fileName;
	DocumentModel	*m_documentModel;

	friend class DocumentModel;
};
