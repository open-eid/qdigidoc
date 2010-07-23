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

#include "TreeWidget.h"

#include "common/Common.h"

#include <digidocpp/Document.h>

#include <QDesktopServices>
#include <QFileDialog>
#include <QFileInfo>
#include <QHeaderView>
#include <QKeyEvent>
#include <QMimeData>
#include <QUrl>

TreeWidget::TreeWidget( QWidget *parent )
:	QTreeWidget( parent )
{
	setColumnCount( 4 );
	header()->setStretchLastSection( false );
	header()->setResizeMode( 0, QHeaderView::Stretch );
	header()->setResizeMode( 1, QHeaderView::ResizeToContents );
	header()->setResizeMode( 2, QHeaderView::ResizeToContents );
	header()->setResizeMode( 3, QHeaderView::ResizeToContents );
	connect( this, SIGNAL(clicked(QModelIndex)), SLOT(clicked(QModelIndex)) );
	connect( this, SIGNAL(doubleClicked(QModelIndex)), SLOT(openFile(QModelIndex)) );
}

void TreeWidget::clicked( const QModelIndex &index )
{
	switch( index.column() )
	{
	case 2:
	{
		QString source = model()->index( index.row(), 0 ).data( Qt::UserRole ).toString();
		QString dest = QFileDialog::getSaveFileName( this,
			tr("Save file"), QString( "%1/%2" )
				.arg( QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ) )
				.arg( model()->index( index.row(), 0 ).data().toString() ) );
		if( !dest.isEmpty() && source != dest )
			QFile::copy( source, dest );
		break;
	}
	case 3: Q_EMIT remove( index.row() ); break;
	default: break;
	}
}

void TreeWidget::keyPressEvent( QKeyEvent *e )
{
	QModelIndexList i = selectionModel()->selectedRows();
	if( hasFocus() && !i.isEmpty() && i[0].isValid() )
	{
		switch( e->key() )
		{
		case Qt::Key_Delete:
			if( !isColumnHidden( 3 ) )
			{
				Q_EMIT remove( i[0].row() );
				e->accept();
			}
			break;
		case Qt::Key_Return:
			openFile( i[0] );
			e->accept();
			break;
		default: break;
		}
	}
	QTreeWidget::keyPressEvent( e );
}

QMimeData* TreeWidget::mimeData( const QList<QTreeWidgetItem*> items ) const
{
	QList<QUrl> list;
	Q_FOREACH( QTreeWidgetItem *item, items )
		list << url( indexFromItem( item ) );
	QMimeData *data = new QMimeData();
	data->setUrls( list );
	return data;
}

QStringList TreeWidget::mimeTypes() const
{ return QStringList() << "text/uri-list"; }

void TreeWidget::openFile( const QModelIndex &index )
{
	QUrl u = url( index );
#ifdef Q_OS_WIN32
	QList<QByteArray> exts = qgetenv( "PATHEXT" ).split(';');
	exts << ".PIF" << ".SCR";
	QFileInfo f( u.toLocalFile() );
	Q_FOREACH( const QByteArray &ext, exts )
	{
		if( QString( ext ).contains( f.suffix(), Qt::CaseInsensitive ) )
			return;
	}
#endif
	QDesktopServices::openUrl( u );
}

void TreeWidget::setContent( const QList<digidoc::Document> &docs )
{
	clear();
	Q_FOREACH( const digidoc::Document &file, docs )
	{
		QTreeWidgetItem *i = new QTreeWidgetItem( this );
		i->setFlags( Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsDragEnabled );

		QFileInfo info( QString::fromUtf8( file.getPath().data() ) );
		i->setText( 0, info.fileName() );
		i->setData( 0, Qt::ToolTipRole, info.fileName() );
		i->setData( 0, Qt::UserRole, info.absoluteFilePath() );

		i->setText( 1, Common::fileSize( info.size() ) );
		i->setData( 1, Qt::TextAlignmentRole, (int)Qt::AlignRight|Qt::AlignVCenter );
		i->setData( 1, Qt::ForegroundRole, Qt::gray );

		i->setData( 2, Qt::DecorationRole, QPixmap(":/images/ico_save.png") );
		i->setData( 2, Qt::ToolTipRole, tr("Save") );
		i->setData( 2, Qt::SizeHintRole, QSize( 20, 20 ) );

		i->setData( 3, Qt::DecorationRole, QPixmap(":/images/ico_delete.png") );
		i->setData( 3, Qt::ToolTipRole, tr("Remove") );
		i->setData( 3, Qt::SizeHintRole, QSize( 20, 20 ) );

		addTopLevelItem( i );
	}
}

Qt::DropActions TreeWidget::supportedDropActions() const
{ return Qt::CopyAction; }

QUrl TreeWidget::url( const QModelIndex &item ) const
{ return QUrl::fromLocalFile( item.model()->index( item.row(), 0 ).data( Qt::UserRole ).toString() ); }
