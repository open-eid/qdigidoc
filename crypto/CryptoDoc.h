/*
 * QDigiDocCrypto
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

#include <QtCore/QStringList>
#include <QtNetwork/QSslCertificate>

class CryptoDoc;
class CDocumentModel: public QAbstractTableModel
{
	Q_OBJECT
public:
	enum Columns
	{
		Name = 0,
		Mime,
		Size,
		Save,
		Remove,

		NColumns
	};

	CDocumentModel( CryptoDoc *doc );

	int columnCount( const QModelIndex &parent = QModelIndex() ) const;
	QVariant data( const QModelIndex &index, int role = Qt::DisplayRole ) const;
	Qt::ItemFlags flags( const QModelIndex &index ) const;
	QMimeData *mimeData( const QModelIndexList &indexes ) const;
	QStringList mimeTypes() const;
	bool removeRows( int row, int count, const QModelIndex &parent = QModelIndex() );
	int rowCount( const QModelIndex &parent = QModelIndex() ) const;

	QString copy( const QModelIndex &index, const QString &path ) const;
	QString mkpath( const QModelIndex &index, const QString &path ) const;

public slots:
	void open( const QModelIndex &index );
	void revert();

private:
	Q_DISABLE_COPY(CDocumentModel)

	CryptoDoc *d;
	QList<QStringList> m_data;

	friend class CDigiDoc;
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

class CryptoDocPrivate;

class CryptoDoc: public QObject
{
	Q_OBJECT
public:
	CryptoDoc( QObject *parent = 0 );
	~CryptoDoc();

	void addFile( const QString &file, const QString &mime );
	bool addKey( const CKey &key );
	void create( const QString &file );
	void clear();
	bool decrypt();
	CDocumentModel* documents() const;
	bool encrypt();
	QString fileName() const;
	bool isEncrypted() const;
	bool isNull() const;
	bool isSigned() const;
	QList<CKey> keys();
	bool open( const QString &file );
	void removeKey( int id );
	void save( const QString &filename = QString() );
	bool saveDDoc( const QString &filename );

private Q_SLOTS:
	void setLastError( const QString &err, int code = -1 );

private:
	bool isEncryptedWarning();

	CryptoDocPrivate *d;

	friend class CDocumentModel;
};
